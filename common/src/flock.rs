//! Advisory whole-file lock on the `credentials.json.lock` sentinel
//! file. Both hub and hub-admin coordinate via this lock when they
//! read-modify-write the credential store.
//!
//! - **Unix:** `flock(2)` with `LOCK_EX`. Released when the file
//!   descriptor is closed (i.e. when `FileLock` drops).
//! - **Windows:** `LockFileEx` with `LOCKFILE_EXCLUSIVE_LOCK` over the
//!   whole file (offset 0, length 0xFFFFFFFF.0xFFFFFFFF). Released
//!   via `UnlockFileEx` in `Drop`.
//!
//! Both are advisory: nothing stops a process from opening the file
//! without taking the lock. We assume our own binaries are the only
//! writers of `credentials.json`.

use std::fs::OpenOptions;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

pub struct FileLock {
    f: std::fs::File,
}

impl FileLock {
    /// Open `path`, take an exclusive whole-file lock. Blocks until
    /// acquired.
    pub fn acquire_exclusive(path: &Path) -> io::Result<Self> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)] opts.mode(0o600);
        let f = opts.open(path)?;
        Self::lock(&f)?;
        Ok(Self { f })
    }

    #[cfg(unix)]
    fn lock(f: &std::fs::File) -> io::Result<()> {
        let fd = f.as_raw_fd();
        // SAFETY: fd is borrowed from `f` and is valid for this call.
        let r = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if r != 0 { return Err(io::Error::last_os_error()); }
        Ok(())
    }

    #[cfg(windows)]
    fn lock(f: &std::fs::File) -> io::Result<()> {
        let mut overlapped = Overlapped::zeroed();
        let r = unsafe {
            LockFileEx(
                f.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if r == 0 { return Err(io::Error::last_os_error()); }
        Ok(())
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // SAFETY: fd is owned by self.f.
            unsafe { libc::flock(self.f.as_raw_fd(), libc::LOCK_UN); }
        }
        #[cfg(windows)]
        {
            let mut overlapped = Overlapped::zeroed();
            unsafe {
                UnlockFileEx(
                    self.f.as_raw_handle(),
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                );
            }
        }
    }
}

// -------- Windows FFI --------

#[cfg(windows)]
#[repr(C)]
struct Overlapped {
    internal:      usize,
    internal_high: usize,
    offset:        u32,
    offset_high:   u32,
    h_event:       *mut core::ffi::c_void,
}

#[cfg(windows)]
impl Overlapped {
    fn zeroed() -> Self {
        Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: core::ptr::null_mut(),
        }
    }
}

#[cfg(windows)]
const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LockFileEx(
        h_file: std::os::windows::raw::HANDLE,
        dw_flags: u32,
        dw_reserved: u32,
        n_bytes_low: u32,
        n_bytes_high: u32,
        lp_overlapped: *mut Overlapped,
    ) -> i32;

    fn UnlockFileEx(
        h_file: std::os::windows::raw::HANDLE,
        dw_reserved: u32,
        n_bytes_low: u32,
        n_bytes_high: u32,
        lp_overlapped: *mut Overlapped,
    ) -> i32;
}
