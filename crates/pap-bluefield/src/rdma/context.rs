//! BlueField device context: opens the ibverbs device and allocates the
//! protection domain (PD) that all memory registrations and QPs share.

use rdma_sys::{
    ibv_alloc_pd, ibv_close_device, ibv_context, ibv_dealloc_pd, ibv_free_device_list,
    ibv_get_device_list, ibv_get_device_name, ibv_gid, ibv_open_device, ibv_pd, ibv_port_attr,
    ibv_query_gid, ibv_query_port,
};

use crate::error::BluefieldError;

/// Constant from libibverbs: Ethernet link layer (RoCEv2).
const IBV_LINK_LAYER_ETHERNET: u8 = 2;

/// Owns an ibverbs device context and its protection domain.
///
/// Drop closes the device automatically.  All [`super::qp::QueuePair`]s and
/// [`super::memory::RegisteredBuffer`]s created from this context must be
/// destroyed before this is dropped (ibverbs will return EBUSY otherwise).
pub struct DeviceContext {
    pub(crate) ctx: *mut ibv_context,
    pub(crate) pd: *mut ibv_pd,
    pub(crate) port_num: u8,
    /// Subnet LID (InfiniBand) or 0 (RoCE/Ethernet).
    pub(crate) lid: u16,
    /// Global Identifier used for RoCEv2 routing.
    pub(crate) gid: ibv_gid,
    /// GID table index selected at open time.
    pub(crate) gid_index: u8,
    /// True when the port uses Ethernet (RoCEv2); false for native IB.
    pub(crate) is_roce: bool,
}

// SAFETY: The ibverbs context is explicitly designed for concurrent use
// from multiple threads.  Protection-domain and QP handles are opaque
// kernel objects; we never alias them.
unsafe impl Send for DeviceContext {}
unsafe impl Sync for DeviceContext {}

impl DeviceContext {
    /// Open a BlueField RDMA device.
    ///
    /// # Arguments
    /// * `device_name` — device to open, e.g. `"mlx5_0"`.  Pass `None` to
    ///   use the first enumerated device (suitable for single-card machines).
    /// * `port_num` — physical port, typically `1`.
    /// * `gid_index` — GID table index; `0` works for most RoCEv2 setups.
    pub fn open(
        device_name: Option<&str>,
        port_num: u8,
        gid_index: u8,
    ) -> Result<Self, BluefieldError> {
        unsafe {
            let mut num_devices: i32 = 0;
            let device_list = ibv_get_device_list(&mut num_devices);

            if device_list.is_null() || num_devices == 0 {
                return Err(BluefieldError::DeviceNotFound(
                    "no RDMA devices found — is MLNX_OFED / DOCA installed?".into(),
                ));
            }

            let devices = std::slice::from_raw_parts(device_list, num_devices as usize);

            // Find the requested device or fall back to the first one.
            let device = match device_name {
                Some(name) => {
                    let found = devices.iter().find(|&&d| {
                        let raw = ibv_get_device_name(d);
                        if raw.is_null() {
                            return false;
                        }
                        std::ffi::CStr::from_ptr(raw)
                            .to_str()
                            .map(|s| s == name)
                            .unwrap_or(false)
                    });
                    ibv_free_device_list(device_list);
                    found.copied().ok_or_else(|| {
                        BluefieldError::DeviceNotFound(format!("'{name}' not found"))
                    })?
                }
                None => {
                    let d = devices[0];
                    ibv_free_device_list(device_list);
                    d
                }
            };

            let ctx = ibv_open_device(device);
            if ctx.is_null() {
                return Err(BluefieldError::DeviceOpenFailed(
                    "ibv_open_device returned null".into(),
                ));
            }

            let pd = ibv_alloc_pd(ctx);
            if pd.is_null() {
                ibv_close_device(ctx);
                return Err(BluefieldError::AllocationFailed(
                    "ibv_alloc_pd failed".into(),
                ));
            }

            // Query port attributes to get the LID and link layer type.
            let mut port_attr = std::mem::zeroed::<ibv_port_attr>();
            let ret = ibv_query_port(ctx, port_num, &mut port_attr as *mut _ as *mut _);
            if ret != 0 {
                ibv_dealloc_pd(pd);
                ibv_close_device(ctx);
                return Err(BluefieldError::RdmaError(format!(
                    "ibv_query_port failed: errno={ret}"
                )));
            }

            let lid = port_attr.lid;
            let is_roce = port_attr.link_layer == IBV_LINK_LAYER_ETHERNET;

            // Query the GID (required for RoCEv2 address handles).
            let mut gid = std::mem::zeroed::<ibv_gid>();
            let ret = ibv_query_gid(ctx, port_num, i32::from(gid_index), &mut gid);
            if ret != 0 {
                ibv_dealloc_pd(pd);
                ibv_close_device(ctx);
                return Err(BluefieldError::RdmaError(format!(
                    "ibv_query_gid(index={gid_index}) failed: errno={ret}"
                )));
            }

            Ok(Self {
                ctx,
                pd,
                port_num,
                lid,
                gid,
                gid_index,
                is_roce,
            })
        }
    }

    /// Device name as reported by libibverbs (e.g. `"mlx5_0"`).
    pub fn device_name(&self) -> &str {
        unsafe {
            let raw = rdma_sys::ibv_get_device_name((*self.ctx).device);
            if raw.is_null() {
                return "<unknown>";
            }
            std::ffi::CStr::from_ptr(raw)
                .to_str()
                .unwrap_or("<invalid utf8>")
        }
    }
}

impl Drop for DeviceContext {
    fn drop(&mut self) {
        unsafe {
            ibv_dealloc_pd(self.pd);
            ibv_close_device(self.ctx);
        }
    }
}
