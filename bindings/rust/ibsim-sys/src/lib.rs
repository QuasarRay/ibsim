//! Raw ABI mirror of `include/ibsim.h`.
//!
//! ibsim sends these structures directly over datagram sockets, so layout is
//! part of the protocol. The simulator uses Linux abstract Unix sockets for
//! local operation; these bindings intentionally target Linux.

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

#[cfg(not(target_os = "linux"))]
compile_error!("ibsim's public socket ABI currently requires Linux");

use libc::{c_char, c_int, sockaddr, sockaddr_in, sockaddr_un};

pub const IBSIM_MAX_CLIENTS: usize = 10;
pub const IBSIM_DEFAULT_SERVER_PORT: u16 = 7070;
pub const SIM_BASENAME: &str = "sim";
pub const SIM_MAGIC: u32 = 0xdead_beef;
pub const SIM_CTL_MAX_DATA: usize = 64;

pub type SIM_CTL_TYPES = c_int;
pub const SIM_CTL_ERROR: SIM_CTL_TYPES = 0;
pub const SIM_CTL_CONNECT: SIM_CTL_TYPES = 1;
pub const SIM_CTL_DISCONNECT: SIM_CTL_TYPES = 2;
pub const SIM_CTL_GET_PORT: SIM_CTL_TYPES = 3;
pub const SIM_CTL_GET_VENDOR: SIM_CTL_TYPES = 4;
pub const SIM_CTL_GET_GID: SIM_CTL_TYPES = 5;
pub const SIM_CTL_GET_GUID: SIM_CTL_TYPES = 6;
pub const SIM_CTL_GET_NODEINFO: SIM_CTL_TYPES = 7;
pub const SIM_CTL_GET_PORTINFO: SIM_CTL_TYPES = 8;
pub const SIM_CTL_SET_ISSM: SIM_CTL_TYPES = 9;
pub const SIM_CTL_GET_PKEYS: SIM_CTL_TYPES = 10;
pub const SIM_CTL_LAST: SIM_CTL_TYPES = 11;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct sim_vendor {
    pub vendor_id: u32,
    pub vendor_part_id: u32,
    pub hw_ver: u32,
    pub fw_ver: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct sim_port {
    pub lid: u16,
    pub state: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct sim_request {
    pub dlid: u32,
    pub slid: u32,
    pub dqp: u32,
    pub sqp: u32,
    pub status: u32,
    pub length: u64,
    pub mad: [c_char; 256],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct sim_ctl {
    pub magic: u32,
    pub clientid: u32,
    pub type_: u32,
    pub len: u32,
    pub data: [c_char; SIM_CTL_MAX_DATA],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct sim_client_info {
    pub id: u32,
    pub qp: u32,
    pub issm: u32,
    pub nodeid: [c_char; 32],
}

#[repr(C)]
pub union name_t {
    pub name: sockaddr,
    pub name_u: sockaddr_un,
    pub name_i: sockaddr_in,
}

macro_rules! zeroed_default {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl Default for $ty {
                fn default() -> Self {
                    // SAFETY: every field is an integer or integer array and
                    // therefore accepts an all-zero bit pattern. Starting from
                    // zero also initializes protocol-visible C padding bytes.
                    unsafe { std::mem::zeroed() }
                }
            }
        )+
    };
}

zeroed_default!(sim_vendor, sim_port, sim_request, sim_ctl, sim_client_info);

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn public_header_layout_matches_x86_64_linux() {
        assert_eq!(size_of::<sim_vendor>(), 24);
        assert_eq!(offset_of!(sim_vendor, vendor_id), 0);
        assert_eq!(offset_of!(sim_vendor, vendor_part_id), 4);
        assert_eq!(offset_of!(sim_vendor, hw_ver), 8);
        assert_eq!(offset_of!(sim_vendor, fw_ver), 16);

        assert_eq!(size_of::<sim_port>(), 4);
        assert_eq!(offset_of!(sim_port, lid), 0);
        assert_eq!(offset_of!(sim_port, state), 2);

        assert_eq!(size_of::<sim_request>(), 288);
        assert_eq!(offset_of!(sim_request, dlid), 0);
        assert_eq!(offset_of!(sim_request, status), 16);
        assert_eq!(offset_of!(sim_request, length), 24);
        assert_eq!(offset_of!(sim_request, mad), 32);

        assert_eq!(size_of::<sim_ctl>(), 80);
        assert_eq!(offset_of!(sim_ctl, data), 16);

        assert_eq!(size_of::<sim_client_info>(), 44);
        assert_eq!(offset_of!(sim_client_info, nodeid), 12);
        assert_eq!(size_of::<name_t>(), 110);
    }
}
