//! Stateful scanner for application OSC sequences in a PTY-output byte
//! stream.
//!
//! An OSC sequence looks like `ESC ] Ps ; Pt ST` where `ST` is either
//! the BEL byte (`0x07`) or `ESC \\` (a "string terminator"). Most OSCs
//! are interpreted by the terminal emulator (window title, OSC 52
//! clipboard, …); we forward them straight to the browser. But our own
//! application-private OSCs (prefix `5111`) trigger server-side actions
//! and must be **stripped** before forwarding, so the user doesn't see
//! the raw escape on the screen.
//!
//! [`OscScanner::feed`] returns:
//! - a `data` slice of bytes to forward as a normal `Data` frame
//!   (everything except our private OSCs — other OSCs ride through
//!   verbatim so e.g. shell `\e]0;title\a` still updates the tab name),
//! - a list of `captured` OSC payloads (without the framing bytes).
//!
//! The scanner is robust against split-across-feed boundaries: state is
//! retained between calls. ESC sequences other than `ESC ]` and
//! `ESC \\` (e.g. CSI `ESC [`, single-char escapes like `ESC c`) are
//! passed through unchanged.
//!
//! Cap: a single OSC is limited to `MAX_OSC_LEN` bytes; longer OSCs
//! are dropped (returned in `captured` so the caller can warn) and
//! NOT forwarded, since we'd otherwise have to buffer arbitrary attacker-
//! controlled bytes. Real OSCs are usually under a few hundred bytes;
//! we use 64 KiB which is more than enough for OSC 52 clipboard payloads
//! and absolute file paths.

/// Cap on a single OSC's payload (the bytes between `ESC ]` and the
/// terminator).
pub const MAX_OSC_LEN: usize = 64 * 1024;

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Normal byte stream; nothing buffered.
    Normal,
    /// Just saw an ESC; waiting to decide what kind of escape it is.
    Esc,
    /// Inside an OSC: accumulating payload bytes.
    Osc,
    /// Inside an OSC and just saw an ESC: if the next byte is `\\`, it
    /// terminates the OSC; otherwise the ESC was part of the payload
    /// and we re-enter `Osc` having added both ESC and the next byte.
    OscEsc,
    /// OSC overflowed `MAX_OSC_LEN` — silently consume bytes until the
    /// terminator, then return to `Normal`. The half-collected payload
    /// is dropped.
    OscOverflow,
    /// Like `OscOverflow` but just saw an ESC; `\\` next ends the OSC.
    OscOverflowEsc,
}

/// Which terminator a fully-received OSC used. Tracked so non-5111
/// OSCs can be re-emitted with the same terminator they arrived with
/// (otherwise we'd silently rewrite ST → BEL, which is fine for xterm
/// but violates the "verbatim" promise in the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Term {
    Bel,
    St,
}

pub struct OscScanner {
    state: State,
    /// Accumulated OSC payload (the bytes between `ESC ]` and the
    /// terminator), waiting to be classified.
    buf: Vec<u8>,
}

impl Default for OscScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl OscScanner {
    pub fn new() -> Self {
        OscScanner {
            state: State::Normal,
            buf: Vec::new(),
        }
    }

    /// Reset scanner state — useful on stream restart.
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.state = State::Normal;
        self.buf.clear();
    }

    /// Feed a chunk of PTY output. Returns
    /// `(forwarded, captured_osc_payloads)`:
    /// - `forwarded` is the byte run to emit as a Data frame to the
    ///   browser (with our 5111-prefixed OSCs removed; everything else
    ///   intact, including non-5111 OSCs and stray ESCs).
    /// - `captured_osc_payloads` is the list of complete OSC payloads
    ///   (without `ESC ]` prefix or terminator) whose first segment
    ///   (before the first `;`) is `"5111"`. Caller dispatches them.
    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut out = Vec::with_capacity(input.len());
        let mut captured = Vec::new();

        for &b in input {
            match self.state {
                State::Normal => {
                    if b == ESC {
                        self.state = State::Esc;
                    } else {
                        out.push(b);
                    }
                }
                State::Esc => {
                    if b == b']' {
                        // Start of OSC. Don't emit anything yet — we'll
                        // either consume it server-side or splice the
                        // whole thing back into `out` once we know.
                        self.state = State::Osc;
                        self.buf.clear();
                    } else {
                        // Some other escape (CSI, single-char). Emit
                        // both bytes and return to Normal.
                        out.push(ESC);
                        out.push(b);
                        self.state = State::Normal;
                    }
                }
                State::Osc => {
                    if b == BEL {
                        self.finish_osc(Term::Bel, &mut out, &mut captured);
                    } else if b == ESC {
                        self.state = State::OscEsc;
                    } else if self.buf.len() < MAX_OSC_LEN {
                        self.buf.push(b);
                    } else {
                        // Overflowed. Drop any partial payload — we'll
                        // never deliver it — and consume to terminator.
                        self.buf.clear();
                        self.state = State::OscOverflow;
                    }
                }
                State::OscEsc => {
                    if b == b'\\' {
                        self.finish_osc(Term::St, &mut out, &mut captured);
                    } else {
                        // Spurious ESC inside OSC payload. Push the ESC
                        // and the byte and stay in Osc.
                        if self.buf.len() + 2 <= MAX_OSC_LEN {
                            self.buf.push(ESC);
                            self.buf.push(b);
                            self.state = State::Osc;
                        } else {
                            self.buf.clear();
                            self.state = State::OscOverflow;
                        }
                    }
                }
                State::OscOverflow => {
                    if b == BEL {
                        self.state = State::Normal;
                    } else if b == ESC {
                        self.state = State::OscOverflowEsc;
                    }
                    // Other bytes are silently consumed.
                }
                State::OscOverflowEsc => {
                    if b == b'\\' {
                        self.state = State::Normal;
                    } else if b == ESC {
                        // Stay in overflow-after-ESC state — could be
                        // ESC ESC ... ESC \\ later.
                    } else {
                        self.state = State::OscOverflow;
                    }
                }
            }
        }
        (out, captured)
    }

    fn finish_osc(&mut self, term: Term, out: &mut Vec<u8>, captured: &mut Vec<Vec<u8>>) {
        // Decide: is this our 5111 application OSC, or someone else's?
        // Look at the prefix up to the first ';'.
        let prefix = self.buf.split(|&b| b == b';').next().unwrap_or(&[]);
        if prefix == b"5111" {
            // Consume it: don't echo to the terminal. Hand the payload
            // (everything after "5111;") to the caller.
            let payload = if self.buf.len() > 5 {
                self.buf[5..].to_vec() // skip "5111;"
            } else {
                Vec::new()
            };
            captured.push(payload);
        } else {
            // Forward verbatim using the same terminator the sender
            // used, so downstream xterm.js sees the same byte sequence
            // it would have without us in the loop.
            out.push(ESC);
            out.push(b']');
            out.extend_from_slice(&self.buf);
            match term {
                Term::Bel => out.push(BEL),
                Term::St => {
                    out.push(ESC);
                    out.push(b'\\');
                }
            }
        }
        self.buf.clear();
        self.state = State::Normal;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut s = OscScanner::new();
        s.feed(input)
    }

    #[test]
    fn passthrough_plain_bytes() {
        let (fwd, caps) = run(b"hello world\n");
        assert_eq!(fwd, b"hello world\n");
        assert!(caps.is_empty());
    }

    #[test]
    fn captures_5111_osc_with_bel() {
        let (fwd, caps) = run(b"before\x1b]5111;dl;/tmp/foo.txt\x07after");
        assert_eq!(fwd, b"beforeafter");
        assert_eq!(caps, vec![b"dl;/tmp/foo.txt".to_vec()]);
    }

    #[test]
    fn captures_5111_osc_with_st() {
        let (fwd, caps) = run(b"x\x1b]5111;dl;/a\x1b\\y");
        assert_eq!(fwd, b"xy");
        assert_eq!(caps, vec![b"dl;/a".to_vec()]);
    }

    #[test]
    fn forwards_non_5111_osc_unchanged() {
        // OSC 0 = set window title.
        let input = b"X\x1b]0;my title\x07Y";
        let (fwd, caps) = run(input);
        assert_eq!(fwd, input);
        assert!(caps.is_empty());
    }

    #[test]
    fn forwards_non_5111_osc_with_st_terminator() {
        // The original terminator (ESC \\) must be preserved when we
        // forward — otherwise we'd silently rewrite ST → BEL.
        let input = b"X\x1b]0;title\x1b\\Y";
        let (fwd, caps) = run(input);
        assert_eq!(fwd, input);
        assert!(caps.is_empty());
    }

    #[test]
    fn overflow_with_stale_esc_does_not_leak_tail_bytes() {
        // Reproduces the rubber-duck-flagged bug where the old
        // overflow handler reused `buf` to track a "last was ESC" flag.
        // A real 5111 OSC that overflowed could end with a stray ESC in
        // its payload right at the cap; the scanner would then accept
        // any subsequent `\\` as a terminator and start forwarding
        // payload tail bytes as normal terminal data.
        //
        // Construction:
        //   ESC ] 5111;XX...X ESC | NEEDLE_THAT_SHOULD_NOT_LEAK |
        //   eventually a real terminator.
        // After fix: tail bytes stay inside OSC overflow and are
        // never emitted to `fwd`.
        let mut input = Vec::from(&b"\x1b]5111;"[..]);
        input.extend(std::iter::repeat_n(b'a', MAX_OSC_LEN));
        input.push(b'\x1b'); // ESC at end of payload — would have been
        // remembered as "last was ESC" by the old impl
        input.extend_from_slice(b"NEEDLE_THAT_SHOULD_NOT_LEAK");
        input.push(b'\x07'); // real BEL terminator
        input.extend_from_slice(b"after");
        let (fwd, caps) = run(&input);
        assert!(caps.is_empty(), "overflow should drop the payload");
        assert!(
            !fwd.windows(6).any(|w| w == b"NEEDLE"),
            "overflow tail leaked: fwd = {:?}",
            String::from_utf8_lossy(&fwd)
        );
        assert_eq!(fwd, b"after");
    }

    #[test]
    fn forwards_osc_52_clipboard_unchanged() {
        let input = b"\x1b]52;c;SGVsbG8=\x07";
        let (fwd, caps) = run(input);
        assert_eq!(fwd, input);
        assert!(caps.is_empty());
    }

    #[test]
    fn stray_esc_passes_through() {
        // ESC c = full reset. Not an OSC.
        let input = b"a\x1bcb";
        let (fwd, caps) = run(input);
        assert_eq!(fwd, input);
        assert!(caps.is_empty());
    }

    #[test]
    fn csi_passes_through() {
        // CSI is ESC [ ... letter. Not an OSC.
        let input = b"\x1b[31mred\x1b[0m";
        let (fwd, caps) = run(input);
        assert_eq!(fwd, input);
        assert!(caps.is_empty());
    }

    #[test]
    fn split_across_feeds_is_robust() {
        // Split the 5111 OSC arbitrarily across many small feeds.
        let mut s = OscScanner::new();
        let full = b"pre\x1b]5111;dl;/foo\x07post";
        let mut fwd_total = Vec::new();
        let mut caps_total: Vec<Vec<u8>> = Vec::new();
        for chunk in full.chunks(1) {
            let (f, c) = s.feed(chunk);
            fwd_total.extend(f);
            caps_total.extend(c);
        }
        assert_eq!(fwd_total, b"prepost");
        assert_eq!(caps_total, vec![b"dl;/foo".to_vec()]);
    }

    #[test]
    fn multiple_captures_in_one_feed() {
        let (fwd, caps) = run(b"a\x1b]5111;dl;/x\x07b\x1b]5111;dl;/y\x07c");
        assert_eq!(fwd, b"abc");
        assert_eq!(caps, vec![b"dl;/x".to_vec(), b"dl;/y".to_vec()]);
    }

    #[test]
    fn mix_5111_with_other_oscs() {
        let (fwd, caps) = run(b"X\x1b]0;title\x07Y\x1b]5111;dl;/p\x07Z\x1b]52;c;Zm9v\x07W");
        assert_eq!(fwd, b"X\x1b]0;title\x07YZ\x1b]52;c;Zm9v\x07W");
        assert_eq!(caps, vec![b"dl;/p".to_vec()]);
    }

    #[test]
    fn empty_5111_payload() {
        // Just "5111;" with nothing after.
        let (fwd, caps) = run(b"\x1b]5111;\x07x");
        assert_eq!(fwd, b"x");
        assert_eq!(caps, vec![Vec::<u8>::new()]);
    }

    #[test]
    fn osc_overflow_drops_silently() {
        let big = vec![b'a'; MAX_OSC_LEN + 100];
        let mut input = Vec::from(&b"X\x1b]5111;"[..]);
        input.extend_from_slice(&big);
        input.extend_from_slice(b"\x07Y");
        let (fwd, caps) = run(&input);
        assert_eq!(fwd, b"XY");
        assert!(caps.is_empty(), "oversized OSC must not be dispatched");
    }

    #[test]
    fn esc_inside_osc_payload_is_kept() {
        // OSC with ESC followed by non-`\\` should treat the ESC as
        // part of the payload, not the start of ST.
        let (fwd, caps) = run(b"\x1b]5111;dl;a\x1bxb\x07");
        assert!(fwd.is_empty());
        assert_eq!(caps, vec![b"dl;a\x1bxb".to_vec()]);
    }
}
