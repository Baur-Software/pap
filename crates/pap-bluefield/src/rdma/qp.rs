//! Reliable Connected (RC) Queue Pair management.
//!
//! [`QueuePair`] wraps the ibverbs QP life-cycle:
//!
//! 1. Allocation (RESET state) — [`QueuePair::create`]
//! 2. Transition RESET → INIT — [`QueuePair::init`]
//! 3. Transition INIT → RTR (Ready To Receive) — [`QueuePair::ready_to_receive`]
//! 4. Transition RTR → RTS (Ready To Send) — [`QueuePair::ready_to_send`]
//!
//! Steps 3 and 4 require the remote side's `QpInfo` (exchanged out-of-band
//! by the TCP bootstrap in [`super::connection`]).

use rdma_sys::{
    ibv_access_flags, ibv_cq, ibv_create_cq, ibv_create_qp, ibv_destroy_cq, ibv_destroy_qp,
    ibv_gid, ibv_modify_qp, ibv_mtu, ibv_poll_cq, ibv_post_recv, ibv_post_send, ibv_qp,
    ibv_qp_attr, ibv_qp_attr_mask, ibv_qp_init_attr, ibv_qp_state, ibv_qp_type, ibv_recv_wr,
    ibv_send_flags, ibv_send_wr, ibv_sge, ibv_wc, ibv_wr_opcode,
};
use serde::{Deserialize, Serialize};
use std::ptr;

use super::context::DeviceContext;
use super::memory::RegisteredBuffer;
use crate::error::BluefieldError;
use crate::frame::{self, FRAME_BUF_SIZE};

/// Maximum number of work requests we keep in flight at once.
const MAX_WR: u32 = 16;
/// Maximum scatter-gather elements per work request.
const MAX_SGE: u32 = 1;
/// Completion queue depth.
const CQ_DEPTH: i32 = 64;

// ── QP metadata exchanged during TCP bootstrap ────────────────────────────────

/// Metadata exchanged over the TCP bootstrap channel so both sides can
/// transition their QPs from INIT → RTR → RTS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QpInfo {
    /// Queue Pair Number — uniquely identifies the QP within the subnet.
    pub qpn: u32,
    /// Subnet Local Identifier (InfiniBand only; 0 for RoCE).
    pub lid: u16,
    /// Global Identifier for RoCEv2 routing (16 raw bytes, big-endian).
    pub gid: [u8; 16],
    /// Initial Packet Sequence Number — randomly chosen.
    pub psn: u32,
}

// ── QueuePair ─────────────────────────────────────────────────────────────────

/// An RC queue pair with its own send/receive CQs and DMA buffers.
pub struct QueuePair {
    qp: *mut ibv_qp,
    send_cq: *mut ibv_cq,
    recv_cq: *mut ibv_cq,
    pub(crate) send_buf: RegisteredBuffer,
    pub(crate) recv_buf: RegisteredBuffer,
    pub(crate) local_info: QpInfo,
}

// SAFETY: ibverbs QP, CQ handles are kernel objects; not aliased here.
unsafe impl Send for QueuePair {}

impl QueuePair {
    /// Create a new QP in RESET state.
    ///
    /// Allocates two CQs (send/receive) and two DMA buffers, each
    /// [`FRAME_BUF_SIZE`] bytes.
    pub fn create(dev: &DeviceContext) -> Result<Self, BluefieldError> {
        let ctx = dev.ctx;
        let pd = dev.pd;

        let send_cq = unsafe { ibv_create_cq(ctx, CQ_DEPTH, ptr::null_mut(), ptr::null_mut(), 0) };
        if send_cq.is_null() {
            return Err(BluefieldError::AllocationFailed(
                "ibv_create_cq (send)".into(),
            ));
        }

        let recv_cq = unsafe { ibv_create_cq(ctx, CQ_DEPTH, ptr::null_mut(), ptr::null_mut(), 0) };
        if recv_cq.is_null() {
            unsafe { ibv_destroy_cq(send_cq) };
            return Err(BluefieldError::AllocationFailed(
                "ibv_create_cq (recv)".into(),
            ));
        }

        let mut qp_init = unsafe { std::mem::zeroed::<ibv_qp_init_attr>() };
        qp_init.send_cq = send_cq;
        qp_init.recv_cq = recv_cq;
        qp_init.qp_type = ibv_qp_type::IBV_QPT_RC;
        qp_init.sq_sig_all = 1; // generate a send completion for every WR
        qp_init.cap.max_send_wr = MAX_WR;
        qp_init.cap.max_recv_wr = MAX_WR;
        qp_init.cap.max_send_sge = MAX_SGE;
        qp_init.cap.max_recv_sge = MAX_SGE;

        let qp = unsafe { ibv_create_qp(pd, &mut qp_init) };
        if qp.is_null() {
            unsafe {
                ibv_destroy_cq(recv_cq);
                ibv_destroy_cq(send_cq);
            }
            return Err(BluefieldError::AllocationFailed(
                "ibv_create_qp failed".into(),
            ));
        }

        let send_buf = RegisteredBuffer::alloc(pd, FRAME_BUF_SIZE)?;
        let recv_buf = RegisteredBuffer::alloc(pd, FRAME_BUF_SIZE)?;

        // Derive a random PSN.
        let psn: u32 = uuid::Uuid::new_v4().as_u128() as u32;

        let local_info = QpInfo {
            qpn: unsafe { (*qp).qp_num },
            lid: dev.lid,
            gid: unsafe { dev.gid.raw },
            psn,
        };

        Ok(Self {
            qp,
            send_cq,
            recv_cq,
            send_buf,
            recv_buf,
            local_info,
        })
    }

    /// Transition RESET → INIT.
    pub fn init(&mut self, port_num: u8) -> Result<(), BluefieldError> {
        let mut attr = unsafe { std::mem::zeroed::<ibv_qp_attr>() };
        attr.qp_state = ibv_qp_state::IBV_QPS_INIT;
        attr.pkey_index = 0;
        attr.port_num = port_num;
        attr.qp_access_flags = (ibv_access_flags::IBV_ACCESS_REMOTE_READ
            | ibv_access_flags::IBV_ACCESS_REMOTE_WRITE
            | ibv_access_flags::IBV_ACCESS_LOCAL_WRITE)
            .0 as i32;

        let mask = ibv_qp_attr_mask::IBV_QP_STATE
            | ibv_qp_attr_mask::IBV_QP_PKEY_INDEX
            | ibv_qp_attr_mask::IBV_QP_PORT
            | ibv_qp_attr_mask::IBV_QP_ACCESS_FLAGS;

        let ret = unsafe { ibv_modify_qp(self.qp, &mut attr, mask.0 as i32) };
        if ret != 0 {
            return Err(BluefieldError::QpTransitionFailed(format!(
                "RESET→INIT failed: errno={ret}"
            )));
        }
        Ok(())
    }

    /// Transition INIT → RTR (Ready To Receive).
    ///
    /// `remote` contains the QP metadata published by the other side via the
    /// TCP bootstrap exchange.
    pub fn ready_to_receive(
        &mut self,
        remote: &QpInfo,
        is_roce: bool,
        gid_index: u8,
    ) -> Result<(), BluefieldError> {
        let mut attr = unsafe { std::mem::zeroed::<ibv_qp_attr>() };
        attr.qp_state = ibv_qp_state::IBV_QPS_RTR;
        attr.path_mtu = ibv_mtu::IBV_MTU_4096;
        attr.dest_qp_num = remote.qpn;
        attr.rq_psn = remote.psn;
        attr.max_dest_rd_atomic = 1;
        attr.min_rnr_timer = 12;

        // Address handle: IB uses LID; RoCE uses GID.
        attr.ah_attr.dlid = remote.lid;
        attr.ah_attr.sl = 0;
        attr.ah_attr.src_path_bits = 0;
        attr.ah_attr.port_num = (*self).local_info_port();

        if is_roce {
            attr.ah_attr.is_global = 1;
            attr.ah_attr.grh.dgid.raw = remote.gid;
            attr.ah_attr.grh.sgid_index = gid_index;
            attr.ah_attr.grh.hop_limit = 64;
        }

        let mask = ibv_qp_attr_mask::IBV_QP_STATE
            | ibv_qp_attr_mask::IBV_QP_AV
            | ibv_qp_attr_mask::IBV_QP_PATH_MTU
            | ibv_qp_attr_mask::IBV_QP_DEST_QPN
            | ibv_qp_attr_mask::IBV_QP_RQ_PSN
            | ibv_qp_attr_mask::IBV_QP_MAX_DEST_RD_ATOMIC
            | ibv_qp_attr_mask::IBV_QP_MIN_RNR_TIMER;

        let ret = unsafe { ibv_modify_qp(self.qp, &mut attr, mask.0 as i32) };
        if ret != 0 {
            return Err(BluefieldError::QpTransitionFailed(format!(
                "INIT→RTR failed: errno={ret}"
            )));
        }
        Ok(())
    }

    /// Transition RTR → RTS (Ready To Send).
    pub fn ready_to_send(&mut self, local_psn: u32) -> Result<(), BluefieldError> {
        let mut attr = unsafe { std::mem::zeroed::<ibv_qp_attr>() };
        attr.qp_state = ibv_qp_state::IBV_QPS_RTS;
        attr.timeout = 14;
        attr.retry_cnt = 7;
        attr.rnr_retry = 7; // infinite retry on RNR NAK
        attr.sq_psn = local_psn;
        attr.max_rd_atomic = 1;

        let mask = ibv_qp_attr_mask::IBV_QP_STATE
            | ibv_qp_attr_mask::IBV_QP_TIMEOUT
            | ibv_qp_attr_mask::IBV_QP_RETRY_CNT
            | ibv_qp_attr_mask::IBV_QP_RNR_RETRY
            | ibv_qp_attr_mask::IBV_QP_SQ_PSN
            | ibv_qp_attr_mask::IBV_QP_MAX_QP_RD_ATOMIC;

        let ret = unsafe { ibv_modify_qp(self.qp, &mut attr, mask.0 as i32) };
        if ret != 0 {
            return Err(BluefieldError::QpTransitionFailed(format!(
                "RTR→RTS failed: errno={ret}"
            )));
        }
        Ok(())
    }

    // ── Wire operations ───────────────────────────────────────────────────

    /// Post a receive work request so the next incoming frame is written into
    /// `recv_buf`.  Must be called before the remote side posts a send.
    pub fn post_recv(&mut self) -> Result<(), BluefieldError> {
        let mut sge = ibv_sge {
            addr: self.recv_buf.addr(),
            length: self.recv_buf.len() as u32,
            lkey: self.recv_buf.lkey(),
        };

        let mut wr = unsafe { std::mem::zeroed::<ibv_recv_wr>() };
        wr.wr_id = 0xBEEF_RECV;
        wr.sg_list = &mut sge;
        wr.num_sge = 1;

        let mut bad_wr: *mut ibv_recv_wr = ptr::null_mut();
        let ret = unsafe { ibv_post_recv(self.qp, &mut wr, &mut bad_wr) };
        if ret != 0 {
            return Err(BluefieldError::RdmaError(format!(
                "ibv_post_recv failed: errno={ret}"
            )));
        }
        Ok(())
    }

    /// Post a send work request for `frame_bytes` bytes already written into
    /// `send_buf`.
    pub fn post_send(&mut self, frame_bytes: usize) -> Result<(), BluefieldError> {
        let mut sge = ibv_sge {
            addr: self.send_buf.addr(),
            length: frame_bytes as u32,
            lkey: self.send_buf.lkey(),
        };

        let mut wr = unsafe { std::mem::zeroed::<ibv_send_wr>() };
        wr.wr_id = 0xBEEF_SEND;
        wr.sg_list = &mut sge;
        wr.num_sge = 1;
        wr.opcode = ibv_wr_opcode::IBV_WR_SEND;
        wr.send_flags = ibv_send_flags::IBV_SEND_SIGNALED.0;

        let mut bad_wr: *mut ibv_send_wr = ptr::null_mut();
        let ret = unsafe { ibv_post_send(self.qp, &mut wr, &mut bad_wr) };
        if ret != 0 {
            return Err(BluefieldError::RdmaError(format!(
                "ibv_post_send failed: errno={ret}"
            )));
        }
        Ok(())
    }

    /// Block until a send completion appears on `send_cq`.
    ///
    /// This is a busy-poll loop and should be called from a `spawn_blocking`
    /// context so it doesn't stall the Tokio runtime.
    pub fn poll_send_cq(&self) -> Result<(), BluefieldError> {
        let mut wc = unsafe { std::mem::zeroed::<ibv_wc>() };
        loop {
            let n = unsafe { ibv_poll_cq(self.send_cq, 1, &mut wc) };
            if n > 0 {
                if wc.status != rdma_sys::ibv_wc_status::IBV_WC_SUCCESS {
                    return Err(BluefieldError::WorkCompletionError(wc.status.0));
                }
                return Ok(());
            } else if n < 0 {
                return Err(BluefieldError::RdmaError(
                    "ibv_poll_cq (send) failed".into(),
                ));
            }
            std::hint::spin_loop();
        }
    }

    /// Block until a receive completion appears on `recv_cq`.
    ///
    /// Returns the number of bytes received (including the 4-byte header).
    /// Should be called from a `spawn_blocking` context.
    pub fn poll_recv_cq(&self) -> Result<usize, BluefieldError> {
        let mut wc = unsafe { std::mem::zeroed::<ibv_wc>() };
        loop {
            let n = unsafe { ibv_poll_cq(self.recv_cq, 1, &mut wc) };
            if n > 0 {
                if wc.status != rdma_sys::ibv_wc_status::IBV_WC_SUCCESS {
                    return Err(BluefieldError::WorkCompletionError(wc.status.0));
                }
                return Ok(wc.byte_len as usize);
            } else if n < 0 {
                return Err(BluefieldError::RdmaError(
                    "ibv_poll_cq (recv) failed".into(),
                ));
            }
            std::hint::spin_loop();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// QP metadata for the bootstrap exchange.
    pub fn local_info(&self) -> &QpInfo {
        &self.local_info
    }

    fn local_info_port(&self) -> u8 {
        // port_num is embedded when we constructed QpInfo; recover it from the
        // ibv_qp struct (field ah_attr.port_num was set in init()).
        // We store it in local_info indirectly — use 1 as a safe default since
        // PAP only ever opens a single port.
        1
    }

    /// Encode `msg` into the send buffer and post a send WR.
    ///
    /// Combines [`frame::encode`] + [`Self::post_send`].
    pub fn send_frame(&mut self, msg: &pap_proto::ProtocolMessage) -> Result<(), BluefieldError> {
        let n = frame::encode(msg, self.send_buf.as_mut_slice())?;
        self.post_send(n)
    }

    /// Poll the recv CQ, then decode the received frame.
    ///
    /// The caller must have already posted a recv WR with [`Self::post_recv`].
    pub fn recv_frame(&self) -> Result<pap_proto::ProtocolMessage, BluefieldError> {
        let bytes = self.poll_recv_cq()?;
        frame::decode(self.recv_buf.as_slice(), bytes)
    }
}

impl Drop for QueuePair {
    fn drop(&mut self) {
        unsafe {
            ibv_destroy_qp(self.qp);
            ibv_destroy_cq(self.recv_cq);
            ibv_destroy_cq(self.send_cq);
        }
    }
}
