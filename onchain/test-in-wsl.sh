#!/usr/bin/env bash
# Full on-chain exercise: build + local validator + deploy + a TS test that publishes a root,
# reads it back, and proves a second root at the same epoch is rejected. WSL only.
#   wsl bash /mnt/<drive>/<path>/onchain/test-in-wsl.sh
set -e
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"
cd "$(dirname "$0")"

[ -f "$HOME/.config/solana/id.json" ] || solana-keygen new --no-bip39-passphrase -o "$HOME/.config/solana/id.json" >/dev/null

echo "=== node deps (yarn install) ==="
yarn install --silent --ignore-engines >/tmp/yarn.log 2>&1 || { echo "yarn failed:"; tail -20 /tmp/yarn.log; exit 1; }

echo "=== anchor keys sync ==="
anchor keys sync 2>&1 | tail -5

echo "=== anchor test (build + validator + deploy + ts-mocha) ==="
anchor test 2>&1 | tail -60
