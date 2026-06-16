#!/usr/bin/env sh
# Build the browser verifier demo (M3):
#   1. emit a fresh signed sample receipt
#   2. compile the RNG-free verifier to WASM for the web target
#   3. tell you how to serve it
#
# Requires: rust toolchain + wasm-pack. Run from the repo root.
set -e

cargo run -q -p pqtl-cli --bin pqtl-emit
wasm-pack build crates/pqtl-wasm --target web --dev --out-dir ../../web/pkg

cat <<'EOF'

Built. Now serve the web/ directory over HTTP (ES modules + fetch need a server):

    cd web && python -m http.server 8080

then open http://localhost:8080 — the honest receipt verifies; click "Tamper" to see it fail.

Headless check (no browser): wasm-pack build crates/pqtl-wasm --target nodejs --dev --out-dir pkg-node && node scripts/wasm-smoke.cjs
EOF
