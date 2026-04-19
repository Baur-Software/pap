//! DMA-capable memory regions for RDMA operations.
//!
//! [`RegisteredBuffer`] wraps a heap-allocated byte array together with an
//! ibverbs memory region (`ibv_mr`).  The buffer is **pinned** — it must not
//! move or be freed while the registration is live.  Drop calls
//! `ibv_dereg_mr` and then releases the heap allocation.

use rdma_sys::{ibv_access_flags, ibv_dereg_mr, ibv_mr, ibv_pd, ibv_reg_mr};

use crate::error::BluefieldError;

/// A fixed-size, ibverbs-registered DMA buffer.
///
/// The inner `Vec<u8>` is heap-allocated and its address is stable for the
/// lifetime of this struct (Rust `Vec` never moves its backing storage unless
/// you call resize / push, which we don't do here).
pub struct RegisteredBuffer {
    /// The actual byte storage.  We keep it in a `Box` to guarantee a stable
    /// heap address.  The length is fixed at construction time.
    buf: Box<[u8]>,
    /// Pointer to the ibverbs memory region.
    mr: *mut ibv_mr,
}

// SAFETY: The buffer is pinned on the heap and the MR handle is a kernel
// object valid until ibv_dereg_mr is called in Drop.
unsafe impl Send for RegisteredBuffer {}

impl RegisteredBuffer {
    /// Allocate and register a zero-initialised buffer of `size` bytes.
    ///
    /// The buffer is registered with `LOCAL_WRITE | REMOTE_READ | REMOTE_WRITE`
    /// access flags so it can be used for both send and receive operations.
    ///
    /// # Safety precondition
    /// `pd` must remain valid (not deallocated) for the lifetime of this
    /// `RegisteredBuffer`.
    pub fn alloc(pd: *mut ibv_pd, size: usize) -> Result<Self, BluefieldError> {
        let buf: Box<[u8]> = vec![0u8; size].into_boxed_slice();

        let access = ibv_access_flags::IBV_ACCESS_LOCAL_WRITE
            | ibv_access_flags::IBV_ACCESS_REMOTE_READ
            | ibv_access_flags::IBV_ACCESS_REMOTE_WRITE;

        let mr = unsafe {
            ibv_reg_mr(
                pd,
                buf.as_ptr() as *mut std::ffi::c_void,
                size,
                access.0 as i32,
            )
        };

        if mr.is_null() {
            return Err(BluefieldError::AllocationFailed(format!(
                "ibv_reg_mr failed for {size}-byte buffer"
            )));
        }

        Ok(Self { buf, mr })
    }

    /// The local key for use in scatter-gather entries.
    #[inline]
    pub fn lkey(&self) -> u32 {
        unsafe { (*self.mr).lkey }
    }

    /// Base address for scatter-gather entries.
    #[inline]
    pub fn addr(&self) -> u64 {
        self.buf.as_ptr() as u64
    }

    /// Buffer capacity in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Mutable byte slice for writing data before a send.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Immutable byte slice for reading data after a receive.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for RegisteredBuffer {
    fn drop(&mut self) {
        unsafe {
            ibv_dereg_mr(self.mr);
        }
    }
}
