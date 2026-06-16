// Node smoke test: runs the WASM verifier (witness-quorum path) against the emitted sample.
// Proves the browser verifier logic works in a real wasm runtime, headlessly.
//   1) build:  wasm-pack build crates/pqtl-wasm --target nodejs --dev --out-dir pkg-node
//   2) sample: cargo run -p pqtl-cli --bin pqtl-emit
//   3) run:    node scripts/wasm-smoke.cjs
const fs = require('fs');
const { verify_receipt_full } = require('../crates/pqtl-wasm/pkg-node/pqtl_wasm.js');

const b = JSON.parse(fs.readFileSync('web/sample-receipt.json', 'utf8'));
const verify = (receipt, cosigned = b.cosigned_sth, witnesses = b.witnesses, threshold = b.threshold) =>
  JSON.parse(verify_receipt_full(
    JSON.stringify(receipt), b.expected_nonce_hex, b.sth_pubkey_hex, b.hardware_root_pubkey_hex,
    JSON.stringify(cosigned), JSON.stringify(witnesses), threshold));

const honest = verify(b.receipt);

const tampered_receipt = JSON.parse(JSON.stringify(b.receipt));
tampered_receipt.sth.signature[0] ^= 1; // flip one bit of the SLH-DSA signature
const tampered = verify(tampered_receipt);

const fewer = JSON.parse(JSON.stringify(b.cosigned_sth));
fewer.cosignatures = fewer.cosignatures.slice(0, 1); // 1 cosignature < threshold 2
const subquorum = verify(b.receipt, fewer);

const noWitnesses = verify(b.receipt, b.cosigned_sth, []); // client pins no witnesses
const zeroThreshold = verify(b.receipt, b.cosigned_sth, b.witnesses, 0); // threshold 0 must be rejected

console.log('honest     :', honest.accepted, '-', honest.reason);
console.log('tampered   :', tampered.accepted, '-', tampered.reason);
console.log('sub-quorum :', subquorum.accepted, '-', subquorum.reason);
console.log('no-witness :', noWitnesses.accepted, '-', noWitnesses.reason);
console.log('thresh=0   :', zeroThreshold.accepted, '-', zeroThreshold.reason);

if (honest.accepted && !tampered.accepted && !subquorum.accepted && !noWitnesses.accepted && !zeroThreshold.accepted) {
  console.log('SMOKE_PASS');
} else {
  console.log('SMOKE_FAIL');
  process.exit(1);
}
