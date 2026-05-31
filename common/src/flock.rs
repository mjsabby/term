//! Advisory whole-file lock via `flock(2)` on the `credentials.json.lock`
//! sentinel file. Both hub and hub-admin coordinate via this lock when
//! they read-modify-write the credential store.

use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

pub struct FileLock {
    f: std::fs::File,
}

impl FileLock {
    /// Open `path`, take an exclusive `flock`. Blocks until acquired.
    pub fn acquire_exclusive(path: &Path) -> io::Result<Self> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        let fd = f.as_raw_fd();
        // SAFETY: fd is owned by `f` which outlives this call.
        let r = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { f })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // SAFETY: fd is owned by self.f.
        unsafe {
            libc::flock(self.f.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
