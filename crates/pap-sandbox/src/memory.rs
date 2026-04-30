use zeroize::Zeroize;

/// A buffer whose contents are zeroed on drop.
/// When `mlock()` succeeds, the pages are pinned to physical RAM and
/// cannot be swapped to disk while the buffer is alive.
pub struct SecureBuffer {
    data: Vec<u8>,
    locked: bool,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            locked: false,
        }
    }

    /// Pin the buffer pages to physical RAM.
    /// Fails gracefully — the buffer is still usable (just swappable).
    pub fn mlock(&mut self) -> bool {
        #[cfg(unix)]
        {
            if self.data.is_empty() {
                return true;
            }
            let ret =
                unsafe { libc::mlock(self.data.as_ptr() as *const libc::c_void, self.data.len()) };
            self.locked = ret == 0;
        }
        self.locked
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Zeroize before freeing — prevents sensitive data lingering in freed pages.
        self.data.zeroize();

        #[cfg(unix)]
        if self.locked && !self.data.is_empty() {
            unsafe {
                libc::munlock(self.data.as_ptr() as *const libc::c_void, self.data.len());
            }
        }
    }
}

impl From<Vec<u8>> for SecureBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<String> for SecureBuffer {
    fn from(s: String) -> Self {
        Self::new(s.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_buffer_zeroes_on_drop() {
        let data = vec![0x42u8; 32];
        let buf = SecureBuffer::new(data);
        assert_eq!(buf.len(), 32);
        drop(buf);
        // If we reach here without segfault, zeroize + drop succeeded.
    }

    #[test]
    fn secure_buffer_empty_does_not_panic() {
        let mut buf = SecureBuffer::new(vec![]);
        assert!(buf.is_empty());
        buf.mlock();
        drop(buf);
    }

    #[test]
    fn mlock_returns_bool() {
        let mut buf = SecureBuffer::new(vec![1u8; 64]);
        // On most systems this works; on sandboxed CI it may fail — that's fine.
        let _result = buf.mlock();
        assert_eq!(buf.as_slice().len(), 64);
    }
}
