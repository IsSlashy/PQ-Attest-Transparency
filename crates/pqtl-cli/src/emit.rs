//! Emits a real, signed session receipt as JSON for the browser/Node verifier to
//! check. Run from the repo root: `cargo run -p pqtl-cli --bin pqtl-emit`.
//! Writes `web/sample-receipt.json`.

use pqtl_core::kem::{self, ClientKeypair};
use pqtl_core::log::TransparencyLog;
use pqtl_core::slh::SlhSigner;
use pqtl_core::witness::Witness;
use pqtl_core::*;

fn main() {
    // An honest loader build, published to the public transparency log.
    let mut log = TransparencyLog::new();
    let signer = SlhSigner::generate().expect("SLH-DSA keygen");
    let qp = MockQuoteProvider::generate(); // mocked hardware root
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

    // Witnesses cosign the honest STH. NOTE: bundling their public keys into the sample below is
    // a DEMO convenience only — a real client MUST pin the witness set out of band, independent of
    // the (provider-produced) receipt, or the anti-split-view property collapses.
    let mut witnesses: Vec<Witness> = (0..3).map(Witness::generate).collect();
    let cosignatures: Vec<_> = witnesses
        .iter_mut()
        .filter_map(|w| w.cosign(&sth, None))
        .collect();
    let cosigned = CosignedSth {
        sth: sth.clone(),
        cosignatures,
    };
    let witness_keys: Vec<_> = witnesses
        .iter()
        .map(|w| serde_json::json!({ "id": w.id(), "pubkey_hex": hex::encode(w.public_key_bytes()) }))
        .collect();

    let bundle = serde_json::json!({
        "receipt": receipt,
        "expected_nonce_hex": hex::encode(nonce.0),
        "sth_pubkey_hex": hex::encode(signer.public_key_bytes()),
        "hardware_root_pubkey_hex": hex::encode(qp.hardware_root_pubkey()),
        "trusted_root_hex": hex::encode(sth.root),
        "cosigned_sth": cosigned,
        "witnesses": witness_keys,
        "threshold": 2,
    });

    std::fs::create_dir_all("web").expect("create web/");
    let path = "web/sample-receipt.json";
    std::fs::write(path, serde_json::to_string_pretty(&bundle).expect("serialize"))
        .expect("write sample receipt");
    println!("wrote {path}  (root={}…, sig={} B)", hex::encode(&sth.root[..4]), sth.signature.len());
}
