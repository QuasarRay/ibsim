//! Safe Rust types for ibsim's public protocol ABI.
//!
//! `include/ibsim.h` is a wire ABI: the C implementation sends its structs
//! directly over datagram sockets. This crate keeps those C-layout details in
//! [`sys`] and exposes validated Rust values plus explicit encode/decode steps.
//! The protocol is native-endian and native-layout by design, just like ibsim.

use std::fmt;
use std::mem::{size_of, MaybeUninit};
use std::ptr;
use std::str;

pub use ibsim_sys as sys;

pub const MAD_CAPACITY: usize = 256;
pub const CONTROL_DATA_CAPACITY: usize = sys::SIM_CTL_MAX_DATA;
pub const NODE_ID_CAPACITY: usize = 31;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidWireSize { expected: usize, actual: usize },
    InvalidMagic(u32),
    UnknownControlType(u32),
    ControlDataTooLong(usize),
    MadTooLong(usize),
    InvalidMadLength(u64),
    NodeIdTooLong(usize),
    NodeIdContainsNul,
    NodeIdNotTerminated,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWireSize { expected, actual } => {
                write!(
                    f,
                    "invalid wire size: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidMagic(value) => write!(f, "invalid ibsim control magic 0x{value:08x}"),
            Self::UnknownControlType(value) => write!(f, "unknown ibsim control type {value}"),
            Self::ControlDataTooLong(len) => {
                write!(
                    f,
                    "control payload is {len} bytes; maximum is {CONTROL_DATA_CAPACITY}"
                )
            }
            Self::MadTooLong(len) => {
                write!(f, "MAD payload is {len} bytes; maximum is {MAD_CAPACITY}")
            }
            Self::InvalidMadLength(len) => {
                write!(f, "wire MAD length {len} exceeds {MAD_CAPACITY}")
            }
            Self::NodeIdTooLong(len) => {
                write!(f, "node ID is {len} bytes; maximum is {NODE_ID_CAPACITY}")
            }
            Self::NodeIdContainsNul => f.write_str("node ID contains an interior NUL byte"),
            Self::NodeIdNotTerminated => f.write_str("wire node ID is not NUL terminated"),
        }
    }
}

impl std::error::Error for Error {}

/// A value with the fixed native C layout used by the ibsim datagram protocol.
pub trait WireMessage: Sized {
    const WIRE_SIZE: usize;

    fn encode(&self) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> Result<Self>;
}

/// Private marker for raw C structs whose every bit pattern is valid.
///
/// All implementations contain only integer scalars and integer arrays.
unsafe trait WirePod: Copy {}
unsafe impl WirePod for sys::sim_vendor {}
unsafe impl WirePod for sys::sim_port {}
unsafe impl WirePod for sys::sim_request {}
unsafe impl WirePod for sys::sim_ctl {}
unsafe impl WirePod for sys::sim_client_info {}

fn encode_raw<T: WirePod>(raw: &T) -> Vec<u8> {
    let mut bytes = vec![0_u8; size_of::<T>()];
    // SAFETY: callers construct raw values from zeroed defaults, so C padding
    // is initialized. `bytes` is exactly the destination object's byte size.
    unsafe {
        ptr::copy_nonoverlapping(
            (raw as *const T).cast::<u8>(),
            bytes.as_mut_ptr(),
            bytes.len(),
        );
    }
    bytes
}

fn decode_raw<T: WirePod>(bytes: &[u8]) -> Result<T> {
    if bytes.len() != size_of::<T>() {
        return Err(Error::InvalidWireSize {
            expected: size_of::<T>(),
            actual: bytes.len(),
        });
    }

    let mut raw = MaybeUninit::<T>::uninit();
    // SAFETY: `T` is restricted to integer-only protocol structs, for which
    // every bit pattern is valid, and exactly `size_of::<T>()` bytes are copied.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), raw.as_mut_ptr().cast::<u8>(), bytes.len());
        Ok(raw.assume_init())
    }
}

fn copy_chars_to_bytes<const N: usize>(source: &[i8; N]) -> [u8; N] {
    let mut output = [0_u8; N];
    for (dst, src) in output.iter_mut().zip(source.iter()) {
        *dst = *src as u8;
    }
    output
}

fn copy_bytes_to_chars<const N: usize>(destination: &mut [i8; N], source: &[u8]) {
    for (dst, src) in destination.iter_mut().zip(source.iter().copied()) {
        *dst = src as i8;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VendorInfo {
    pub vendor_id: u32,
    pub vendor_part_id: u32,
    pub hardware_version: u32,
    pub firmware_version: u64,
}

impl From<sys::sim_vendor> for VendorInfo {
    fn from(raw: sys::sim_vendor) -> Self {
        Self {
            vendor_id: raw.vendor_id,
            vendor_part_id: raw.vendor_part_id,
            hardware_version: raw.hw_ver,
            firmware_version: raw.fw_ver,
        }
    }
}

impl From<VendorInfo> for sys::sim_vendor {
    fn from(value: VendorInfo) -> Self {
        let mut raw = Self::default();
        raw.vendor_id = value.vendor_id;
        raw.vendor_part_id = value.vendor_part_id;
        raw.hw_ver = value.hardware_version;
        raw.fw_ver = value.firmware_version;
        raw
    }
}

impl WireMessage for VendorInfo {
    const WIRE_SIZE: usize = size_of::<sys::sim_vendor>();

    fn encode(&self) -> Vec<u8> {
        encode_raw(&sys::sim_vendor::from(*self))
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        decode_raw::<sys::sim_vendor>(bytes).map(Into::into)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortInfo {
    pub lid: u16,
    pub state: u8,
}

impl From<sys::sim_port> for PortInfo {
    fn from(raw: sys::sim_port) -> Self {
        Self {
            lid: raw.lid,
            state: raw.state,
        }
    }
}

impl From<PortInfo> for sys::sim_port {
    fn from(value: PortInfo) -> Self {
        let mut raw = Self::default();
        raw.lid = value.lid;
        raw.state = value.state;
        raw
    }
}

impl WireMessage for PortInfo {
    const WIRE_SIZE: usize = size_of::<sys::sim_port>();

    fn encode(&self) -> Vec<u8> {
        encode_raw(&sys::sim_port::from(*self))
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        decode_raw::<sys::sim_port>(bytes).map(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MadRequest {
    dlid: u32,
    slid: u32,
    destination_qp: u32,
    source_qp: u32,
    status: u32,
    payload: Vec<u8>,
}

impl MadRequest {
    pub fn new(
        dlid: u32,
        slid: u32,
        destination_qp: u32,
        source_qp: u32,
        status: u32,
        payload: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let payload = payload.as_ref();
        if payload.len() > MAD_CAPACITY {
            return Err(Error::MadTooLong(payload.len()));
        }
        Ok(Self {
            dlid,
            slid,
            destination_qp,
            source_qp,
            status,
            payload: payload.to_vec(),
        })
    }

    pub const fn dlid(&self) -> u32 {
        self.dlid
    }

    pub const fn slid(&self) -> u32 {
        self.slid
    }

    pub const fn destination_qp(&self) -> u32 {
        self.destination_qp
    }

    pub const fn source_qp(&self) -> u32 {
        self.source_qp
    }

    pub const fn status(&self) -> u32 {
        self.status
    }

    pub fn set_status(&mut self, status: u32) {
        self.status = status;
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn set_payload(&mut self, payload: impl AsRef<[u8]>) -> Result<()> {
        let payload = payload.as_ref();
        if payload.len() > MAD_CAPACITY {
            return Err(Error::MadTooLong(payload.len()));
        }
        self.payload.clear();
        self.payload.extend_from_slice(payload);
        Ok(())
    }
}

impl WireMessage for MadRequest {
    const WIRE_SIZE: usize = size_of::<sys::sim_request>();

    fn encode(&self) -> Vec<u8> {
        let mut raw = sys::sim_request::default();
        raw.dlid = self.dlid;
        raw.slid = self.slid;
        raw.dqp = self.destination_qp;
        raw.sqp = self.source_qp;
        raw.status = self.status;
        raw.length = self.payload.len() as u64;
        copy_bytes_to_chars(&mut raw.mad, &self.payload);
        encode_raw(&raw)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let raw = decode_raw::<sys::sim_request>(bytes)?;
        let len = usize::try_from(raw.length).map_err(|_| Error::InvalidMadLength(raw.length))?;
        if len > MAD_CAPACITY {
            return Err(Error::InvalidMadLength(raw.length));
        }
        let mad = copy_chars_to_bytes(&raw.mad);
        Ok(Self {
            dlid: raw.dlid,
            slid: raw.slid,
            destination_qp: raw.dqp,
            source_qp: raw.sqp,
            status: raw.status,
            payload: mad[..len].to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ControlType {
    Error = sys::SIM_CTL_ERROR as u32,
    Connect = sys::SIM_CTL_CONNECT as u32,
    Disconnect = sys::SIM_CTL_DISCONNECT as u32,
    GetPort = sys::SIM_CTL_GET_PORT as u32,
    GetVendor = sys::SIM_CTL_GET_VENDOR as u32,
    GetGid = sys::SIM_CTL_GET_GID as u32,
    GetGuid = sys::SIM_CTL_GET_GUID as u32,
    GetNodeInfo = sys::SIM_CTL_GET_NODEINFO as u32,
    GetPortInfo = sys::SIM_CTL_GET_PORTINFO as u32,
    SetIsSm = sys::SIM_CTL_SET_ISSM as u32,
    GetPKeys = sys::SIM_CTL_GET_PKEYS as u32,
}

impl ControlType {
    pub const fn as_raw(self) -> u32 {
        self as u32
    }
}

impl TryFrom<u32> for ControlType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            value if value == Self::Error as u32 => Ok(Self::Error),
            value if value == Self::Connect as u32 => Ok(Self::Connect),
            value if value == Self::Disconnect as u32 => Ok(Self::Disconnect),
            value if value == Self::GetPort as u32 => Ok(Self::GetPort),
            value if value == Self::GetVendor as u32 => Ok(Self::GetVendor),
            value if value == Self::GetGid as u32 => Ok(Self::GetGid),
            value if value == Self::GetGuid as u32 => Ok(Self::GetGuid),
            value if value == Self::GetNodeInfo as u32 => Ok(Self::GetNodeInfo),
            value if value == Self::GetPortInfo as u32 => Ok(Self::GetPortInfo),
            value if value == Self::SetIsSm as u32 => Ok(Self::SetIsSm),
            value if value == Self::GetPKeys as u32 => Ok(Self::GetPKeys),
            _ => Err(Error::UnknownControlType(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlMessage {
    client_id: u32,
    kind: ControlType,
    data: Vec<u8>,
}

impl ControlMessage {
    pub fn new(client_id: u32, kind: ControlType, data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        if data.len() > CONTROL_DATA_CAPACITY {
            return Err(Error::ControlDataTooLong(data.len()));
        }
        Ok(Self {
            client_id,
            kind,
            data: data.to_vec(),
        })
    }

    fn query(client_id: u32, kind: ControlType, len: usize) -> Self {
        debug_assert!(len <= CONTROL_DATA_CAPACITY);
        Self {
            client_id,
            kind,
            data: vec![0_u8; len],
        }
    }

    pub fn connect(info: &ClientInfo) -> Self {
        Self {
            client_id: 0,
            kind: ControlType::Connect,
            data: info.encode(),
        }
    }

    pub fn disconnect(client_id: u32) -> Self {
        Self::query(client_id, ControlType::Disconnect, 0)
    }

    pub fn get_port(client_id: u32) -> Self {
        Self::query(client_id, ControlType::GetPort, PortInfo::WIRE_SIZE)
    }

    pub fn get_vendor(client_id: u32) -> Self {
        Self::query(client_id, ControlType::GetVendor, VendorInfo::WIRE_SIZE)
    }

    pub fn get_gid(client_id: u32) -> Self {
        Self::query(client_id, ControlType::GetGid, 16)
    }

    pub fn get_guid(client_id: u32) -> Self {
        Self::query(client_id, ControlType::GetGuid, 8)
    }

    pub fn get_node_info(client_id: u32) -> Self {
        Self::query(client_id, ControlType::GetNodeInfo, CONTROL_DATA_CAPACITY)
    }

    pub fn get_port_info(client_id: u32, port_number: u8) -> Self {
        let mut message = Self::query(client_id, ControlType::GetPortInfo, CONTROL_DATA_CAPACITY);
        message.data[0] = port_number;
        message
    }

    pub fn set_is_sm(client_id: u32, enabled: bool) -> Self {
        Self {
            client_id,
            kind: ControlType::SetIsSm,
            data: (if enabled { 1_u32 } else { 0_u32 })
                .to_ne_bytes()
                .to_vec(),
        }
    }

    pub fn get_pkeys(client_id: u32) -> Self {
        Self::query(client_id, ControlType::GetPKeys, CONTROL_DATA_CAPACITY)
    }

    pub const fn client_id(&self) -> u32 {
        self.client_id
    }

    pub const fn kind(&self) -> ControlType {
        self.kind
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn decode_payload<T: WireMessage>(&self) -> Result<T> {
        T::decode(&self.data)
    }
}

impl WireMessage for ControlMessage {
    const WIRE_SIZE: usize = size_of::<sys::sim_ctl>();

    fn encode(&self) -> Vec<u8> {
        let mut raw = sys::sim_ctl::default();
        raw.magic = sys::SIM_MAGIC;
        raw.clientid = self.client_id;
        raw.type_ = self.kind.as_raw();
        raw.len = self.data.len() as u32;
        copy_bytes_to_chars(&mut raw.data, &self.data);
        encode_raw(&raw)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let raw = decode_raw::<sys::sim_ctl>(bytes)?;
        if raw.magic != sys::SIM_MAGIC {
            return Err(Error::InvalidMagic(raw.magic));
        }
        let kind = ControlType::try_from(raw.type_)?;
        let len = raw.len as usize;
        if len > CONTROL_DATA_CAPACITY {
            return Err(Error::ControlDataTooLong(len));
        }
        let data = copy_chars_to_bytes(&raw.data);
        Ok(Self {
            client_id: raw.clientid,
            kind,
            data: data[..len].to_vec(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientInfo {
    id: u32,
    qp: u32,
    is_sm: bool,
    node_id: Vec<u8>,
}

impl ClientInfo {
    pub fn new(id: u32, qp: u32, is_sm: bool, node_id: impl AsRef<[u8]>) -> Result<Self> {
        let node_id = node_id.as_ref();
        if node_id.len() > NODE_ID_CAPACITY {
            return Err(Error::NodeIdTooLong(node_id.len()));
        }
        if node_id.contains(&0) {
            return Err(Error::NodeIdContainsNul);
        }
        Ok(Self {
            id,
            qp,
            is_sm,
            node_id: node_id.to_vec(),
        })
    }

    pub const fn id(&self) -> u32 {
        self.id
    }

    pub const fn qp(&self) -> u32 {
        self.qp
    }

    pub const fn is_sm(&self) -> bool {
        self.is_sm
    }

    pub fn node_id(&self) -> &[u8] {
        &self.node_id
    }

    pub fn node_id_str(&self) -> Option<&str> {
        str::from_utf8(&self.node_id).ok()
    }
}

impl WireMessage for ClientInfo {
    const WIRE_SIZE: usize = size_of::<sys::sim_client_info>();

    fn encode(&self) -> Vec<u8> {
        let mut raw = sys::sim_client_info::default();
        raw.id = self.id;
        raw.qp = self.qp;
        raw.issm = if self.is_sm { 1 } else { 0 };
        copy_bytes_to_chars(&mut raw.nodeid, &self.node_id);
        encode_raw(&raw)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let raw = decode_raw::<sys::sim_client_info>(bytes)?;
        let node_id = copy_chars_to_bytes(&raw.nodeid);
        let end = node_id
            .iter()
            .position(|&byte| byte == 0)
            .ok_or(Error::NodeIdNotTerminated)?;
        Self::new(raw.id, raw.qp, raw.issm != 0, &node_id[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_info_round_trip() {
        let info = ClientInfo::new(42, 1, true, b"H-1").unwrap();
        assert_eq!(ClientInfo::decode(&info.encode()).unwrap(), info);
    }

    #[test]
    fn control_connect_round_trip() {
        let info = ClientInfo::new(99, 0, false, b"node-a").unwrap();
        let message = ControlMessage::connect(&info);
        let decoded = ControlMessage::decode(&message.encode()).unwrap();
        assert_eq!(decoded.kind(), ControlType::Connect);
        assert_eq!(decoded.decode_payload::<ClientInfo>().unwrap(), info);
    }

    #[test]
    fn mad_round_trip_preserves_payload() {
        let request = MadRequest::new(1, 2, 3, 4, 0, [1_u8, 2, 3, 4]).unwrap();
        assert_eq!(MadRequest::decode(&request.encode()).unwrap(), request);
    }

    #[test]
    fn control_magic_is_validated() {
        let mut bytes = ControlMessage::get_vendor(1).encode();
        bytes[0] ^= 1;
        assert!(matches!(
            ControlMessage::decode(&bytes),
            Err(Error::InvalidMagic(_))
        ));
    }

    #[test]
    fn constructors_enforce_fixed_buffers() {
        assert!(matches!(
            MadRequest::new(0, 0, 0, 0, 0, [0_u8; MAD_CAPACITY + 1]),
            Err(Error::MadTooLong(_))
        ));
        assert!(matches!(
            ClientInfo::new(0, 0, false, vec![b'x'; NODE_ID_CAPACITY + 1]),
            Err(Error::NodeIdTooLong(_))
        ));
    }
}
