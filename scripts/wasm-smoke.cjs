// Node smoke test: runs the WASM verifier against the emitted sample receipt.
// Proves the browser verifier logic works in a real wasm runtime, headlessly.
//   1) build:  wasm-pack build crates/pqtl-wasm --target nodejs --dev --out-dir pkg-node
//   2) sample: cargo run -p pqtl-cli --bin pqtl-emit
//   3) run:    node scripts/wasm-smoke.cjs
const fs = require('fs');
const { verify_receipt_json } = require('../crates/pqtl-wasm/pkg-node/pqtl_wasm.js');

const b = JSON.parse(fs.readFileSync('web/sample-receipt.json', 'utf8'));
const verify = (receipt, root = b.trusted_root_hex) =>
  JSON.parse(verify_receipt_json(
    JSON.stringify(receipt), b.expected_nonce_hex, b.sth_pubkey_hex, b.hardware_root_pubkey_hex, root));

const honest = verify(b.receipt);

const tampered_receipt = JSON.parse(JSON.stringify(b.receipt));
tampered_receipt.sth.signature[0] ^= 1; // flip one bit of the SLH-DSA signature
const tampered = verify(tampered_receipt);

const splitview = verify(b.receipt, '00'.repeat(32)); // root the witnesses never saw

console.log('honest    :', honest.accepted, '-', honest.reason);
console.log('tampered  :', tampered.accepted, '-', tampered.reason);
console.log('split-view:', splitview.accepted, '-', splitview.reason);

if (honest.accepted && !tampered.accepted && !splitview.accepted) {
  console.log('SMOKE_PASS');
} else {
  console.log('SMOKE_FAIL');
  process.exit(1);
}
