#!/usr/bin/env bash
# Build the sth-anchor Solana program with cargo build-sbf, from WSL.
#   wsl bash /mnt/d/PQ-Attest-Transparency/onchain/build-in-wsl.sh
set -e
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"
cd "$(dirname "$0")"
echo "cargo:     $(cargo --version)"
echo "build-sbf: $(cargo-build-sbf --version | head -1)"
echo "=== building ==="
cargo build-sbf --manifest-path programs/sth-anchor/Cargo.toml
echo "=== artifact(s) ==="
find . -name '*.so' -newermt '-10 minutes' 2>/dev/null | while read -r f; do
  ls -la "$f"
done
