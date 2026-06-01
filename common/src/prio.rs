//! Priority, byte-bounded mpsc channels.
//!
//! `BytesTx` / `BytesRx` wrap a `tokio::sync::mpsc::UnboundedSender` with a
//! `Semaphore` permit, so capacity is enforced in **bytes**, not items —
//! which matters when message sizes range from a few bytes (Data
//! keystrokes) to 1 MiB (PasteChunk).
//!
//! `PrioTx` / `PrioRx` pair two `BytesTx`/`BytesRx` (one "hi", one "lo")
//! with a biased receiver: hi is always polled first, so interactive
//! frames never sit behind bulk upload chunks. Senders pick the half
//! explicitly. Both halves track closed state independently, so the
//! receiver only returns `None` when *both* halves are drained AND
//! closed.
//!
//! Capacity semantics: the per-message permit is released when the
//! receiver pulls the item off the channel — not when the consumer is
//! done with it. This is a slight under-estimate of bytes in flight,
//! bounded by the consumer's downstream socket/PTY write buffer.

use std::sync::Arc;

use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

/// A byte-bounded multi-producer, single-consumer sender. Each `send`
/// acquires `bytes.len()` permits from a shared `Semaphore`; the permit
/// is released when the receiver pulls the item.
#[derive(Clone)]
pub struct BytesTx {
    tx:  mpsc::UnboundedSender<(OwnedSemaphorePermit, Vec<u8>)>,
    sem: Arc<Semaphore>,
    /// Cached so we can reject obvious oversized sends synchronously
    /// instead of awaiting forever.
    cap: usize,
}

pub struct BytesRx {
    rx: mpsc::UnboundedReceiver<(OwnedSemaphorePermit, Vec<u8>)>,
}

/// Create a byte-bounded channel with the given capacity, in bytes.
pub fn bytes_channel(cap_bytes: usize) -> (BytesTx, BytesRx) {
    // Cap u32: Semaphore counts are u32. acquire_many_owned takes u32.
    // Bound to u32::MAX permits.
    let permits = cap_bytes.min(u32::MAX as usize);
    let sem = Arc::new(Semaphore::new(permits));
    let (tx, rx) = mpsc::unbounded_channel();
    (BytesTx { tx, sem, cap: permits }, BytesRx { rx })
}

impl BytesTx {
    /// Send `bytes`, blocking the caller until enough capacity is free.
    /// Returns `Err(bytes)` if the channel is closed (returning the
    /// payload so callers can recover it if useful).
    pub async fn send(&self, bytes: Vec<u8>) -> Result<(), Vec<u8>> {
        if bytes.len() > self.cap {
            // Would deadlock: payload bigger than the channel's total
            // capacity. Treat as a closed channel since the only fix is
            // a code change.
            return Err(bytes);
        }
        let n = bytes.len() as u32;
        let permit = match self.sem.clone().acquire_many_owned(n).await {
            Ok(p)  => p,
            Err(_) => return Err(bytes), // semaphore closed
        };
        match self.tx.send((permit, bytes)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::SendError((_, b))) => Err(b),
        }
    }

    /// True if the receiver has dropped.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

impl BytesRx {
    /// Receive the next message, releasing its byte budget. Returns
    /// `None` after all senders drop AND the queue is drained.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        // The permit drops at the end of this function, freeing its
        // byte budget for new sends.
        let (_permit, bytes) = self.rx.recv().await?;
        Some(bytes)
    }
}

/// Two-priority byte-bounded channel sender. Senders pick the half;
/// the receiver biases hi over lo.
#[derive(Clone)]
pub struct PrioTx {
    pub hi: BytesTx,
    pub lo: BytesTx,
}

pub struct PrioRx {
    hi: BytesRx,
    lo: BytesRx,
    hi_closed: bool,
    lo_closed: bool,
}

/// Create a priority channel with separate hi/lo byte budgets.
pub fn prio_channel(cap_hi_bytes: usize, cap_lo_bytes: usize) -> (PrioTx, PrioRx) {
    let (htx, hrx) = bytes_channel(cap_hi_bytes);
    let (ltx, lrx) = bytes_channel(cap_lo_bytes);
    (
        PrioTx { hi: htx, lo: ltx },
        PrioRx { hi: hrx, lo: lrx, hi_closed: false, lo_closed: false },
    )
}

impl PrioRx {
    /// Receive the next message, preferring `hi`. Returns `None` only
    /// once both halves are closed AND fully drained.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.hi_closed && self.lo_closed { return None; }
            // The `if !self.X_closed` guards skip a closed half so we
            // don't busy-loop on its always-None recv future.
            tokio::select! {
                biased;
                v = self.hi.recv(), if !self.hi_closed => match v {
                    Some(x) => return Some(x),
                    None    => { self.hi_closed = true; }
                },
                v = self.lo.recv(), if !self.lo_closed => match v {
                    Some(x) => return Some(x),
                    None    => { self.lo_closed = true; }
                },
            }
        }
    }
}

// --- generic, item-count-bounded priority channel ------------------------
//
// `BytesTx`/`PrioTx` above can only carry contiguous `Vec<u8>` payloads,
// which is fine for the socket-writer queue. For typed channels that
// move enums whose memory isn't trivially countable (e.g. `Body`), use
// `ItemPrioTx`/`ItemPrioRx`: bounded by item count, not bytes, but with
// the same biased-hi-then-lo receive discipline.

/// Generic priority mpsc sender. Cheap to clone (cloning both halves).
pub struct ItemPrioTx<T> {
    pub hi: mpsc::Sender<T>,
    pub lo: mpsc::Sender<T>,
}

impl<T> Clone for ItemPrioTx<T> {
    fn clone(&self) -> Self {
        ItemPrioTx { hi: self.hi.clone(), lo: self.lo.clone() }
    }
}

pub struct ItemPrioRx<T> {
    hi: mpsc::Receiver<T>,
    lo: mpsc::Receiver<T>,
    hi_closed: bool,
    lo_closed: bool,
}

/// Create an item-count-bounded priority channel.
pub fn item_prio_channel<T>(cap_hi: usize, cap_lo: usize) -> (ItemPrioTx<T>, ItemPrioRx<T>) {
    let (htx, hrx) = mpsc::channel(cap_hi);
    let (ltx, lrx) = mpsc::channel(cap_lo);
    (
        ItemPrioTx { hi: htx, lo: ltx },
        ItemPrioRx { hi: hrx, lo: lrx, hi_closed: false, lo_closed: false },
    )
}

impl<T> ItemPrioRx<T> {
    /// Receive the next message, preferring `hi`. Returns `None` only
    /// once both halves are closed AND fully drained.
    pub async fn recv(&mut self) -> Option<T> {
        loop {
            if self.hi_closed && self.lo_closed { return None; }
            tokio::select! {
                biased;
                v = self.hi.recv(), if !self.hi_closed => match v {
                    Some(x) => return Some(x),
                    None    => { self.hi_closed = true; }
                },
                v = self.lo.recv(), if !self.lo_closed => match v {
                    Some(x) => return Some(x),
                    None    => { self.lo_closed = true; }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bytes_channel_round_trips() {
        let (tx, mut rx) = bytes_channel(16);
        tx.send(b"hi".to_vec()).await.unwrap();
        tx.send(b"there".to_vec()).await.unwrap();
        assert_eq!(rx.recv().await.as_deref(), Some(&b"hi"[..]));
        assert_eq!(rx.recv().await.as_deref(), Some(&b"there"[..]));
    }

    #[tokio::test]
    async fn bytes_channel_enforces_byte_cap() {
        let (tx, mut rx) = bytes_channel(8);
        // Two 4-byte sends should succeed without blocking.
        tx.send(vec![0u8; 4]).await.unwrap();
        tx.send(vec![0u8; 4]).await.unwrap();

        // Third send must block until the receiver drains some. Spawn
        // it so we can advance the receiver in this task.
        let tx2 = tx.clone();
        let send_handle = tokio::spawn(async move {
            tx2.send(vec![0u8; 4]).await
        });
        // Without a recv, the send should still be waiting.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!send_handle.is_finished());
        // Drain one to unblock.
        let got = rx.recv().await.unwrap();
        assert_eq!(got.len(), 4);
        send_handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn bytes_channel_rejects_oversize_payload() {
        let (tx, _rx) = bytes_channel(8);
        let r = tx.send(vec![0u8; 9]).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn prio_channel_prefers_hi() {
        let (tx, mut rx) = prio_channel(64, 64);
        tx.lo.send(b"low".to_vec()).await.unwrap();
        tx.hi.send(b"high".to_vec()).await.unwrap();
        // Bias should pull hi first even though lo was sent earlier.
        // Note: the order between two ready halves under tokio::select!
        // biased is deterministic top-down, so hi wins.
        let first = rx.recv().await.unwrap();
        assert_eq!(first, b"high");
        let second = rx.recv().await.unwrap();
        assert_eq!(second, b"low");
    }

    #[tokio::test]
    async fn prio_channel_drains_both_after_close() {
        let (tx, mut rx) = prio_channel(64, 64);
        tx.hi.send(b"a".to_vec()).await.unwrap();
        tx.lo.send(b"b".to_vec()).await.unwrap();
        tx.hi.send(b"c".to_vec()).await.unwrap();
        drop(tx);
        let mut seen: Vec<Vec<u8>> = Vec::new();
        while let Some(v) = rx.recv().await { seen.push(v); }
        assert_eq!(seen.len(), 3);
        // After close + drain, recv must return None.
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn prio_channel_independent_budgets() {
        // hi is small (16B), lo is large (1024B). Saturating lo
        // shouldn't block hi sends.
        let (tx, mut rx) = prio_channel(16, 1024);
        // Fill lo near capacity; sends should succeed.
        for _ in 0..10 {
            tx.lo.send(vec![0u8; 100]).await.unwrap();
        }
        // hi should still accept a small send instantly.
        let send_hi = tokio::spawn({
            let tx = tx.clone();
            async move { tx.hi.send(b"hi!".to_vec()).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(send_hi.is_finished());
        send_hi.await.unwrap().unwrap();
        // Drain hi via the priority receiver.
        let first = rx.recv().await.unwrap();
        assert_eq!(first, b"hi!");
    }

    #[tokio::test]
    async fn item_prio_channel_prefers_hi_and_drains() {
        let (tx, mut rx) = item_prio_channel::<u32>(4, 4);
        tx.lo.send(1).await.unwrap();
        tx.lo.send(2).await.unwrap();
        tx.hi.send(10).await.unwrap();
        tx.hi.send(11).await.unwrap();
        drop(tx);
        let mut seen = Vec::new();
        while let Some(v) = rx.recv().await { seen.push(v); }
        // hi values first, then lo, in send order within each half.
        assert_eq!(seen, vec![10, 11, 1, 2]);
        assert!(rx.recv().await.is_none());
    }
}
