#![allow(dead_code)]
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

// SBI extension and function IDs
const SBI_YIELD: usize = 9;

// CMIO buffer addresses
pub const PMA_CMIO_RX_BUFFER_START: usize = 0x60000000;
pub const PMA_CMIO_TX_BUFFER_START: usize = 0x60800000;

pub const HTIF_DEVICE_YIELD: u8 = 2;
pub const HTIF_YIELD_CMD_MANUAL: u8 = 1;

pub fn sbi_yield(req: u64) -> usize {
    unsafe { sbi::ecall1(req as usize, SBI_YIELD, 0) }.unwrap_or(0)
}

pub fn pack_yield(dev: u8, cmd: u8, reason: u16, data: u32) -> u64 {
    ((dev as u64) << 56) | ((cmd as u64) << 48) | ((reason as u64) << 32) | (data as u64)
}

pub struct CMIODriver {
    rx_base: usize,
    tx_base: usize,
}

impl CMIODriver {
    pub const fn new() -> Self {
        Self {
            rx_base: PMA_CMIO_RX_BUFFER_START,
            tx_base: PMA_CMIO_TX_BUFFER_START,
        }
    }

    pub fn tx_write(&self, data: &[u8]) -> usize {
        unsafe {
            let dst_payload = core::slice::from_raw_parts_mut(self.tx_base as *mut u8, data.len());
            dst_payload.copy_from_slice(data);
        }

        data.len()
    }

    pub fn rx_read(&self, rx_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; rx_len];
        unsafe {
            let src = core::slice::from_raw_parts(self.rx_base as *const u8, rx_len);
            out.copy_from_slice(src);
        }

        out
    }
}
