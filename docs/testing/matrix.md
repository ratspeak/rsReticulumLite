# Testing

Run `./scripts/test-matrix.sh` after the setup in the [README](../../README.md).

| Check | Coverage |
| --- | --- |
| Host tests | Wire encoding, announces, routing, bounded tables, proofs, IFAC, ratchets and Resource handling. |
| Trusted compatibility | Byte-level and bidirectional checks against the pinned rsReticulum implementation. |
| Isolated relay | A simulated topology with no direct endpoint-to-endpoint path. |
| Bare-metal builds | `thumbv7em-none-eabihf` and `riscv32imc-unknown-none-elf`. |
| Dependency checks | No host runtime, OS entropy or interface dependencies in the production graph. |
| API fixture | Representative downstream usage in a separate Cargo workspace. |
| Formatting, Clippy and rustdoc | Warnings denied and public documentation links checked. |
| Source checks | Package metadata, source pins, workflow permissions and repository hygiene. |

## Python interoperability

`./vectors/run.sh` exchanges Rust-produced Resource data with Python Reticulum
and checks the reverse direction. From the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install "rns==$(cat vectors/RNS_VERSION)"
./vectors/run.sh
```

[`vectors/RNS_VERSION`](../../vectors/RNS_VERSION) selects the reference version.

The committed Resource vectors cover advertisements, ciphertext parts,
requests and proofs. Regenerate them with `vectors/gen_resource_vectors.py`
only when the reference or fixture changes, then inspect the diff.

`./scripts/release-matrix.sh` runs all of the above and requires the exact
`TRUSTED_REF` checkout. Ordinary development warns on source drift; release
checks fail.

Radio drivers, flash behavior and timing under load must be tested in the
consuming firmware.
