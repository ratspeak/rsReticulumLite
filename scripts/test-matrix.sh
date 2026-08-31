#!/usr/bin/env sh
set -eu

./scripts/check-trusted-ref.sh
cargo metadata --format-version 1 --locked --no-deps >/dev/null
python3 scripts/check-source.py
cargo fmt --all --check
cargo fmt --manifest-path tests/api/Cargo.toml -- --check
cargo check --workspace --all-targets --locked
cargo check --workspace --target thumbv7em-none-eabihf --locked
cargo check --workspace --target riscv32imc-unknown-none-elf --locked
cargo tree -p rns-lite-core --target thumbv7em-none-eabihf -e=no-dev --locked > target/rns-lite-core-no-std-tree.txt
if grep -E "getrandom|tokio|rns-transport|rns-interface|serialport|socket2" target/rns-lite-core-no-std-tree.txt; then
  echo "forbidden host dependency found in production no_std tree" >&2
  exit 1
fi
cargo tree -p rns-lite-core --target riscv32imc-unknown-none-elf -e=no-dev --locked > target/rns-lite-core-riscv-no-std-tree.txt
if grep -E "getrandom|tokio|rns-transport|rns-interface|serialport|socket2" target/rns-lite-core-riscv-no-std-tree.txt; then
  echo "forbidden host dependency found in production RISC-V no_std tree" >&2
  exit 1
fi
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo test --workspace --locked
cargo check --manifest-path tests/api/Cargo.toml --locked
./scripts/check-trusted-ref.sh
