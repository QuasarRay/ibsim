# Rust bindings for ibsim

This directory contains Rust bindings for the public API declared by
`include/ibsim.h`.

ibsim is different from a typical C library: its installed public header is the
native-layout datagram protocol shared by the simulator and `umad2sim`. The
internal `umad2sim/sim_client.h` helpers are not installed as public API, so the
Rust crates intentionally bind the public protocol rather than the LD_PRELOAD
implementation details.

## Crates

- `ibsim-sys` mirrors the constants, structures, control enum values, and
  `name_t` socket-address union from `include/ibsim.h` with C layout.
- `ibsim` exposes owned and validated `VendorInfo`, `PortInfo`, `MadRequest`,
  `ClientInfo`, `ControlType`, and `ControlMessage` values plus fixed-layout
  encoding/decoding through `WireMessage`.

## Safety and protocol model

The C implementation writes `sim_ctl` and `sim_request` structures directly to
datagram sockets. Consequently this protocol is **native-endian and
native-layout**; it is not a portable network serialization format. A Rust
client and an ibsim server must use compatible ABIs, matching the existing C
client/server requirement.

The high-level crate avoids exposing mutable fixed-size C buffers. It validates:

- `SIM_MAGIC` on every decoded control frame;
- control type values and the 64-byte control payload limit;
- the 256-byte MAD payload limit and decoded MAD length;
- the 31-byte NUL-terminated node-ID limit.

Raw structs are zero-initialized before encoding so protocol-visible C padding
never contains uninitialized Rust bytes.

## Build and test

The bindings do not link to `libumad2sim` or require InfiniBand development
libraries because the public API contains no callable functions.

```sh
cargo fmt --manifest-path bindings/rust/Cargo.toml --all -- --check
cargo check --manifest-path bindings/rust/Cargo.toml --workspace --all-targets
cargo test --manifest-path bindings/rust/Cargo.toml --workspace
cargo clippy --manifest-path bindings/rust/Cargo.toml --workspace --all-targets -- -D warnings
```

The current local-socket ABI uses Linux abstract Unix sockets, matching ibsim's
implementation, so `ibsim-sys` intentionally targets Linux.

## Example

```rust
use ibsim::{ClientInfo, ControlMessage, ControlType, WireMessage};

let client = ClientInfo::new(1234, 0, false, b"H-1")?;
let request = ControlMessage::connect(&client);
let datagram = request.encode();

let decoded = ControlMessage::decode(&datagram)?;
assert_eq!(decoded.kind(), ControlType::Connect);
assert_eq!(decoded.decode_payload::<ClientInfo>()?, client);
# Ok::<(), ibsim::Error>(())
```
