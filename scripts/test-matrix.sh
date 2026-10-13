#!/usr/bin/env sh
set -eu

./scripts/check-trusted-ref.sh
cargo +1.87.0 metadata --format-version 1 --locked --no-deps >/dev/null
python3 scripts/check-source.py
cargo +1.87.0 fmt --all --check
cargo +1.87.0 fmt --manifest-path tests/api/Cargo.toml -- --check
# The production no_std library keeps its MCU MSRV. Host parity tests compile
# the trusted full Rust donor, whose independent minimum is Rust 1.89.
cargo +1.87.0 check --workspace --lib --locked
cargo +1.89.0 check --workspace --all-targets --locked
cargo +1.87.0 check --workspace --lib --target thumbv7em-none-eabihf --locked
cargo +1.87.0 check --workspace --lib --target riscv32imc-unknown-none-elf --locked
mkdir -p target
cargo +1.87.0 tree -p rns-lite-core --target thumbv7em-none-eabihf -e=no-dev --locked > target/rns-lite-core-no-std-tree.txt
if grep -E "getrandom|tokio|rns-transport|rns-interface|serialport|socket2" target/rns-lite-core-no-std-tree.txt; then
  echo "forbidden host dependency found in production no_std tree" >&2
  exit 1
fi
cargo +1.87.0 tree -p rns-lite-core --target riscv32imc-unknown-none-elf -e=no-dev --locked > target/rns-lite-core-riscv-no-std-tree.txt
if grep -E "getrandom|tokio|rns-transport|rns-interface|serialport|socket2" target/rns-lite-core-riscv-no-std-tree.txt; then
  echo "forbidden host dependency found in production RISC-V no_std tree" >&2
  exit 1
fi
cargo +1.87.0 clippy --workspace --lib --locked -- -D warnings
cargo +1.89.0 clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo +1.87.0 doc --workspace --no-deps --locked
cargo +1.89.0 test --workspace --locked
cargo +1.87.0 check --manifest-path tests/api/Cargo.toml --locked
./scripts/check-trusted-ref.sh
