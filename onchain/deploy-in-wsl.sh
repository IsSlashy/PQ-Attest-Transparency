#!/usr/bin/env bash
# Spin up a local validator, deploy sth_anchor.so, and confirm it is on-chain. WSL only.
#   wsl bash /mnt/d/PQ-Attest-Transparency/onchain/deploy-in-wsl.sh
set -e
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"
cd "$(dirname "$0")"

rm -rf /tmp/sth-ledger
solana-keygen new --no-bip39-passphrase --force -o /tmp/deployer.json >/dev/null 2>&1
solana config set -ul -k /tmp/deployer.json >/dev/null

solana-test-validator -r --ledger /tmp/sth-ledger >/tmp/validator.log 2>&1 &
VPID=$!
trap 'kill $VPID 2>/dev/null || true' EXIT

echo "waiting for validator..."
for _ in $(seq 1 40); do
  if solana cluster-version >/dev/null 2>&1; then break; fi
  sleep 1
done
echo "cluster: $(solana cluster-version 2>&1)"

for _ in 1 2 3 4 5; do solana airdrop 10 >/dev/null 2>&1 && break; sleep 2; done
echo "balance: $(solana balance 2>&1)"

echo "=== deploying ==="
PROGRAM_ID=$(solana program deploy target/deploy/sth_anchor.so --output json 2>/tmp/deploy.err \
  | grep -oP '"programId":\s*"\K[^"]+' || true)
if [ -z "$PROGRAM_ID" ]; then
  echo "DEPLOY FAILED:"; cat /tmp/deploy.err; exit 1
fi
echo "DEPLOYED_PROGRAM_ID=$PROGRAM_ID"
echo "=== solana program show ==="
solana program show "$PROGRAM_ID" 2>&1 | head -10
