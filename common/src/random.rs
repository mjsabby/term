//! OS-RNG helper. Always available (no feature gate); used by the
//! agent for per-session download tokens, by the webauthn module for
//! challenges, and by creds.rs for the HMAC secret.
//!
//! Implementation:
//! - Unix: read from `/dev/urandom`. Documented as the right interface
//!   for "give me cryptographic randomness" on all current Linux/BSD/
//!   macOS; never blocks once the kernel's entropy pool is seeded
//!   (which happens well before user space starts).
//! - Windows: `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
//!   No handle bookkeeping; the kernel handles entropy.
//!
//! Panics on failure. Random bytes are mandatory and the failure
//! modes (kernel RNG init error, EFAULT) all warrant an immediate
//! abort rather than papering over with "best effort" pseudo-random.

/// Fill `buf` with OS random bytes.
pub fn fill(buf: &mut [u8]) {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
        f.read_exact(buf).expect("read /dev/urandom");
    }
    #[cfg(windows)]
    {
        // BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x02.
        #[link(name = "bcrypt")]
        unsafe extern "system" {
            fn BCryptGenRandom(
                hAlgorithm: *mut core::ffi::c_void,
                pbBuffer: *mut u8,
                cbBuffer: u32,
                dwFlags: u32,
            ) -> i32;
        }
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x02;
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            panic!("BCryptGenRandom failed: status=0x{:x}", status as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_draws_differ() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a);
        fill(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn fills_each_byte_eventually() {
        // Statistically: with 1024 bytes we should see most byte
        // values appear. (P(any one value missing) = (255/256)^1024
        // ≈ 0.018; over 100 trials a stuck-zero RNG would be obvious.)
        let mut buf = [0u8; 1024];
        fill(&mut buf);
        let nonzero = buf.iter().filter(|&&b| b != 0).count();
        assert!(nonzero > 990, "RNG produced too many zeros: {nonzero}/1024");
    }
}
