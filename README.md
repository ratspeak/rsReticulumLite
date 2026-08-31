# rsReticulumLite

[![CI](https://github.com/ratspeak/rsReticulumLite/actions/workflows/ci.yml/badge.svg)](https://github.com/ratspeak/rsReticulumLite/actions/workflows/ci.yml)
[![Rust 1.87+](https://img.shields.io/badge/rust-1.87%2B-orange.svg)](https://www.rust-lang.org)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)

**Reticulum in Rust for microcontrollers.**

`rns-lite-core` provides transport and endpoint primitives adapted from
[rsReticulum](https://github.com/ratspeak/rsReticulum). It is `no_std`,
allocation-free, and uses fixed-capacity buffers and tables. The firmware
supplies clocks, entropy, storage and interface I/O.

## Scope

- Packet encoding, signed announces, path discovery and transport forwarding.
- Link handshake, session encryption, proofs and optional IFAC.
- Bounded Resource transfers and persistent ratchet/known-destination encodings.
- LoRa split framing, airtime limiting and carrier-sense backoff.
- `MicroNode` and `SmallNode` profiles, with custom capacities through `LiteNode`.

Resource endpoints support encrypted, uncompressed, single-segment transfers:
up to eight parts and 3,659 bytes of application data. This limit does not
restrict a relay forwarding Resource packets between other endpoints.

This is a protocol library, not a board driver or complete Reticulum runtime.
Link scheduling, durable writes and transmission outcomes remain with the
caller. LXMF message encoding lives in [rsLXMFLite](https://github.com/ratspeak/rsLXMFLite).

## Build and test

Install Rust through `rustup`; the repository selects Rust 1.87 and the
bare-metal check targets. From a new working directory:

```sh
git clone https://github.com/ratspeak/rsReticulumLite.git
git clone https://github.com/ratspeak/rsReticulum.git
cd rsReticulumLite
while read -r repository revision; do
  git -C "../$repository" checkout --detach "$revision"
done < TRUSTED_REF
./scripts/test-matrix.sh
```

The matrix runs host tests, ARM/RISC-V checks, Clippy, rustdoc and compatibility
tests against the exact rsReticulum revision in [`TRUSTED_REF`](TRUSTED_REF).
Python Resource checks are described in the [testing notes](docs/testing/matrix.md#python-interoperability).

For a firmware dependency, pin a source revision:

```toml
[dependencies]
rns-lite-core = { git = "https://github.com/ratspeak/rsReticulumLite", rev = "<commit>" }
```

The crate is distributed from source, not crates.io.
See the [path-request example](crates/rns-lite-core/examples/path_request.rs)
and [integration notes](docs/architecture/lite-transport-node.md).
Build API documentation with `cargo doc --workspace --no-deps --open`.

## License

[AGPL-3.0-or-later](LICENSE).
