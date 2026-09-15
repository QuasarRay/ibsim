//! Safe Rust types for ibsim's public protocol ABI.
//!
//! `include/ibsim.h` is a wire ABI: the C implementation sends its structs
//! directly over datagram sockets. This crate keeps those C-layout details in
//! [`sys`] and exposes validated Rust values plus explicit encode/decode steps.
//! The protocol is native-endian and native-layout by design, just like ibsim.

use std::fmt;
use std::mem::{offset_of, size_of};
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

fn check_wire_size<T>(bytes: &[u8]) -> Result<()> {
    let expected = size_of::<T>();
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::InvalidWireSize {
            expected,
            actual: bytes.len(),
        })
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut value = [0_u8; 2];
    value.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_ne_bytes(value)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0_u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_ne_bytes(value)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_ne_bytes(value)
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
        Self {
            vendor_id: value.vendor_id,
            vendor_part_id: value.vendor_part_id,
            hw_ver: value.hardware_version,
            fw_ver: value.firmware_version,
        }
    }
}

impl WireMessage for VendorInfo {
    const WIRE_SIZE: usize = size_of::<sys::sim_vendor>();

    fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![0_u8; Self::WIRE_SIZE];
        write_u32(
            &mut bytes,
            offset_of!(sys::sim_vendor, vendor_id),
            self.vendor_id,
        );
        write_u32(
            &mut bytes,
            offset_of!(sys::sim_vendor, vendor_part_id),
            self.vendor_part_id,
        );
        write_u32(
            &mut bytes,
            offset_of!(sys::sim_vendor, hw_ver),
            self.hardware_version,
        );
        write_u64(
            &mut bytes,
            offset_of!(sys::sim_vendor, fw_ver),
            self.firmware_version,
        );
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        check_wire_size::<sys::sim_vendor>(bytes)?;
        Ok(Self {
            vendor_id: read_u32(bytes, offset_of!(sys::sim_vendor, vendor_id)),
            vendor_part_id: read_u32(bytes, offset_of!(sys::sim_vendor, vendor_part_id)),
            hardware_version: read_u32(bytes, offset_of!(sys::sim_vendor, hw_ver)),
            firmware_version: read_u64(bytes, offset_of!(sys::sim_vendor, fw_ver)),
        })
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
        Self {
            lid: value.lid,
            state: value.state,
        }
    }
}

impl WireMessage for PortInfo {
    const WIRE_SIZE: usize = size_of::<sys::sim_port>();

    fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![0_u8; Self::WIRE_SIZE];
        write_u16(&mut bytes, offset_of!(sys::sim_port, lid), self.lid);
        bytes[offset_of!(sys::sim_port, state)] = self.state;
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        check_wire_size::<sys::sim_port>(bytes)?;
        Ok(Self {
            lid: read_u16(bytes, offset_of!(sys::sim_port, lid)),
            state: bytes[offset_of!(sys::sim_port, state)],
        })
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
        let mut bytes = vec![0_u8; Self::WIRE_SIZE];
        write_u32(&mut bytes, offset_of!(sys::sim_request, dlid), self.dlid);
        write_u32(&mut bytes, offset_of!(sys::sim_request, slid), self.slid);
        write_u32(
            &mut bytes,
            offset_of!(sys::sim_request, dqp),
            self.destination_qp,
        );
        write_u32(
            &mut bytes,
            offset_of!(sys::sim_request, sqp),
            self.source_qp,
        );
        write_u32(
            &mut bytes,
            offset_of!(sys::sim_request, status),
            self.status,
        );
        write_u64(
            &mut bytes,
            offset_of!(sys::sim_request, length),
            self.payload.len() as u64,
        );
        let mad = offset_of!(sys::sim_request, mad);
        bytes[mad..mad + self.payload.len()].copy_from_slice(&self.payload);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        check_wire_size::<sys::sim_request>(bytes)?;
        let raw_length = read_u64(bytes, offset_of!(sys::sim_request, length));
        let len = usize::try_from(raw_length).map_err(|_| Error::InvalidMadLength(raw_length))?;
        if len > MAD_CAPACITY {
            return Err(Error::InvalidMadLength(raw_length));
        }
        let mad = offset_of!(sys::sim_request, mad);
        Ok(Self {
            dlid: read_u32(bytes, offset_of!(sys::sim_request, dlid)),
            slid: read_u32(bytes, offset_of!(sys::sim_request, slid)),
            destination_qp: read_u32(bytes, offset_of!(sys::sim_request, dqp)),
            source_qp: read_u32(bytes, offset_of!(sys::sim_request, sqp)),
            status: read_u32(bytes, offset_of!(sys::sim_request, status)),
            payload: bytes[mad..mad + len].to_vec(),
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
            data: (if enabled { 1_u32 } else { 0_u32 }).to_ne_bytes().to_vec(),
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
        let mut bytes = vec![0_u8; Self::WIRE_SIZE];
        write_u32(&mut bytes, offset_of!(sys::sim_ctl, magic), sys::SIM_MAGIC);
        write_u32(
            &mut bytes,
            offset_of!(sys::sim_ctl, clientid),
            self.client_id,
        );
        write_u32(
            &mut bytes,
            offset_of!(sys::sim_ctl, type_),
            self.kind.as_raw(),
        );
        write_u32(
            &mut bytes,
            offset_of!(sys::sim_ctl, len),
            self.data.len() as u32,
        );
        let data = offset_of!(sys::sim_ctl, data);
        bytes[data..data + self.data.len()].copy_from_slice(&self.data);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        check_wire_size::<sys::sim_ctl>(bytes)?;
        let magic = read_u32(bytes, offset_of!(sys::sim_ctl, magic));
        if magic != sys::SIM_MAGIC {
            return Err(Error::InvalidMagic(magic));
        }
        let kind = ControlType::try_from(read_u32(bytes, offset_of!(sys::sim_ctl, type_)))?;
        let len = read_u32(bytes, offset_of!(sys::sim_ctl, len)) as usize;
        if len > CONTROL_DATA_CAPACITY {
            return Err(Error::ControlDataTooLong(len));
        }
        let data = offset_of!(sys::sim_ctl, data);
        Ok(Self {
            client_id: read_u32(bytes, offset_of!(sys::sim_ctl, clientid)),
            kind,
            data: bytes[data..data + len].to_vec(),
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
        let mut bytes = vec![0_u8; Self::WIRE_SIZE];
        write_u32(&mut bytes, offset_of!(sys::sim_client_info, id), self.id);
        write_u32(&mut bytes, offset_of!(sys::sim_client_info, qp), self.qp);
        write_u32(
            &mut bytes,
            offset_of!(sys::sim_client_info, issm),
            if self.is_sm { 1 } else { 0 },
        );
        let nodeid = offset_of!(sys::sim_client_info, nodeid);
        bytes[nodeid..nodeid + self.node_id.len()].copy_from_slice(&self.node_id);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        check_wire_size::<sys::sim_client_info>(bytes)?;
        let nodeid = offset_of!(sys::sim_client_info, nodeid);
        let node_bytes = &bytes[nodeid..nodeid + 32];
        let end = node_bytes
            .iter()
            .position(|&byte| byte == 0)
            .ok_or(Error::NodeIdNotTerminated)?;
        Self::new(
            read_u32(bytes, offset_of!(sys::sim_client_info, id)),
            read_u32(bytes, offset_of!(sys::sim_client_info, qp)),
            read_u32(bytes, offset_of!(sys::sim_client_info, issm)) != 0,
            &node_bytes[..end],
        )
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
