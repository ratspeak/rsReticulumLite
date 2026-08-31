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

Resources sent or received by this library are limited to 3,659 bytes of data
per transfer. Transfers are encrypted; compression and multi-segment transfers
are not supported. This size limit does not apply when forwarding Resource
packets between other nodes.

The library does not run a networking loop or drive hardware. Your firmware
manages Link timers, writes persistent state and handles transmission failures.
For LXMF messages, use [rsLXMFLite](https://github.com/ratspeak/rsLXMFLite).

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
For Python interoperability checks, install the RNS version in
[`vectors/RNS_VERSION`](vectors/RNS_VERSION) and run `./vectors/run.sh`.

For a firmware dependency, pin a source revision:

```toml
[dependencies]
rns-lite-core = { git = "https://github.com/ratspeak/rsReticulumLite", rev = "<commit>" }
```

The crate is distributed from source, not crates.io.
See the [path-request example](examples/path_request.rs).
Build API documentation with `cargo doc --workspace --no-deps --open`.

## License

[AGPL-3.0-or-later](LICENSE).
