//! Emits a real, signed session receipt as JSON for the browser/Node verifier to
//! check. Run from the repo root: `cargo run -p pqtl-cli --bin pqtl-emit`.
//! Writes `web/sample-receipt.json`.

use pqtl_core::kem::{self, ClientKeypair};
use pqtl_core::log::TransparencyLog;
use pqtl_core::slh::SlhSigner;
use pqtl_core::*;

fn main() {
    // An honest loader build, published to the public transparency log.
    let mut log = TransparencyLog::new();
    let signer = SlhSigner::generate().expect("SLH-DSA keygen");
    let qp = MockQuoteProvider;
    let honest = Measurement(sha256(&[b"loader-build:", b"v1.0-honest", b"<honest loader bytes>"]));
    let idx = log.append(&honest);
    let sth = log.signed_tree_head(&signer);

    // A client session: real X-Wing public key in the binding, real key release.
    let nonce = Nonce(sha256(&[b"client-session-nonce-1"]));
    let client = ClientKeypair::generate();
    let kem_pub = client.public_key();
    let (ciphertext, _shared) = kem::encapsulate(&kem_pub.0).expect("encapsulate");

    let receipt = Receipt {
        quote: qp.quote(&nonce, &kem_pub, &honest),
        nonce: nonce.clone(),
        kem_pubkey: kem_pub,
        kem_ciphertext: ciphertext,
        inclusion: log.inclusion_proof(idx).expect("inclusion"),
        sth: sth.clone(),
    };

    let bundle = serde_json::json!({
        "receipt": receipt,
        "expected_nonce_hex": hex::encode(nonce.0),
        "sth_pubkey_hex": hex::encode(signer.public_key_bytes()),
        "trusted_root_hex": hex::encode(sth.root),
    });

    std::fs::create_dir_all("web").expect("create web/");
    let path = "web/sample-receipt.json";
    std::fs::write(path, serde_json::to_string_pretty(&bundle).expect("serialize"))
        .expect("write sample receipt");
    println!("wrote {path}  (root={}…, sig={} B)", hex::encode(&sth.root[..4]), sth.signature.len());
}
