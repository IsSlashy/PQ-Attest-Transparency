//! M0 walking-skeleton demo.
//!
//! Drives the two paths the artifact exists to show, end to end, with PLACEHOLDER
//! crypto (SHA-256 stand-ins; real ML-KEM/SLH-DSA arrive in M1–M2):
//!   1. a build that is publicly logged + attested  -> key released, client accepts.
//!   2. a "ghost" build that is NOT logged (a targeted/split-view attack) -> the
//!      keyserver policy refuses, and even a forged receipt is caught client-side.
//!
//! The point: the client refuses a loader that classic attestation alone would accept.

use pqtl_core::kem::{derive_session_key, encapsulate, ClientKeypair};
use pqtl_core::log::{verify_consistency, TransparencyLog};
use pqtl_core::slh::SlhSigner;
use pqtl_core::verify::verify_receipt;
use pqtl_core::*;

fn measurement_of(label: &str, build: &[u8]) -> Measurement {
    Measurement(sha256(&[b"loader-build:", label.as_bytes(), build]))
}

fn hex8(h: &Hash) -> String {
    h.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Keyserver release policy: issue the key-release (an X-Wing ciphertext) + a
/// client-verifiable receipt ONLY if the attested measurement is in the public log.
/// Returns the receipt and the keyserver-side session key; `None` = release refused.
fn keyserver_issue(
    log: &TransparencyLog,
    signer: &dyn SthSigner,
    qp: &dyn QuoteProvider,
    nonce: &Nonce,
    kem: &KemPublicKey,
    measurement: &Measurement,
) -> Option<(Receipt, [u8; 32])> {
    let idx = log.find(measurement)?; // policy gate: must be publicly logged
    let (ciphertext, shared) = encapsulate(&kem.0)?; // HNDL-safe key release
    let session_key = derive_session_key(&shared, nonce, &ciphertext, measurement);
    let receipt = Receipt {
        quote: qp.quote(nonce, kem, measurement),
        nonce: nonce.clone(),
        kem_pubkey: kem.clone(),
        kem_ciphertext: ciphertext,
        inclusion: log.inclusion_proof(idx)?,
        sth: log.signed_tree_head(signer),
    };
    Some((receipt, session_key))
}

fn main() {
    println!("== PQ-Attest-Transparency — M2 : binding HNDL-safe X25519+ML-KEM-768 (X-Wing) ==");
    println!("   (STH = SLH-DSA réel ; log = inclusion + consistance RFC6962)\n");

    // Public transparency log + its operator's SLH-DSA signer + the anchor.
    let mut log = TransparencyLog::new();
    let signer = SlhSigner::generate().expect("SLH-DSA keygen");
    let verifier = signer.verifier(); // what the client holds — public key only
    let qp = MockQuoteProvider;
    let mut anchor = LocalAnchor::default();

    // An honest loader build, published to the public log.
    let honest = measurement_of("v1.0-honest", b"<honest loader bytes>");
    let idx = log.append(&honest);
    let sth0 = log.signed_tree_head(&signer);
    anchor.anchor(&sth0); // witnesses see this root
    println!(
        "[log] build honnête publié  idx={idx}  root={}…  taille={}",
        hex8(&sth0.root),
        sth0.tree_size
    );
    println!(
        "[bench] STH signé SLH-DSA-SHA2-128s : signature {} o, clé publique {} o (réf. ECDSA ~64–72 o).",
        sth0.signature.len(),
        signer.public_key_bytes().len()
    );

    let nonce = Nonce(sha256(&[b"client-session-nonce-1"]));
    let client = ClientKeypair::generate();
    let kem = client.public_key(); // real X-Wing public key (1216 B)

    // ---------------- Scenario 1: honest, logged build ----------------
    println!("\n--- Scénario 1 : build loggé + attesté ---");
    match keyserver_issue(&log, &signer, &qp, &nonce, &kem, &honest) {
        Some((receipt, server_key)) => {
            print!(
                "[keyserver] mesure présente → clé encapsulée (X-Wing, ct {} o), reçu émis.\n            ",
                receipt.kem_ciphertext.len()
            );
            match verify_receipt(&receipt, &nonce, &verifier, &anchor) {
                Ok(()) => println!("[client] reçu vérifié (binding+inclusion+STH+anchor) → ✅ ACCEPTÉ"),
                Err(e) => println!("[client] ❌ refus inattendu : {e:?}"),
            }
            // Establish the HNDL-safe session key by decapsulating; confirm it matches.
            let shared = client
                .decapsulate(&receipt.kem_ciphertext)
                .expect("décapsulation");
            let client_key = derive_session_key(&shared, &nonce, &receipt.kem_ciphertext, &honest);
            if client_key == server_key {
                println!("            [client] canal de session établi : clé identique des deux côtés (HNDL-safe)");
            } else {
                println!("            [client] ❌ clé de session divergente (BUG)");
            }
        }
        None => println!("[keyserver] refus inattendu pour un build honnête (BUG)"),
    }

    // ---------------- Scenario 2: targeted ghost build ----------------
    println!("\n--- Scénario 2 : build « fantôme » non loggé (attaque ciblée / split-view) ---");
    let ghost = measurement_of("v1.0-backdoored", b"<backdoored loader bytes>");

    // 2a. An honest keyserver refuses outright: the measurement isn't in the log.
    match keyserver_issue(&log, &signer, &qp, &nonce, &kem, &ghost) {
        Some(_) => println!("[keyserver] (anormal) a émis un reçu pour un build non loggé (BUG)"),
        None => println!("[keyserver] mesure ABSENTE du log → release refusé (politique) → ❌"),
    }

    // 2b. A COMPROMISED keyserver forges a receipt anyway, reusing the honest build's
    //     inclusion proof. The client must still catch it.
    let forged = Receipt {
        quote: qp.quote(&nonce, &kem, &ghost),
        nonce: nonce.clone(),
        kem_pubkey: kem.clone(),
        kem_ciphertext: Vec::new(),
        inclusion: log.inclusion_proof(idx).unwrap(), // proof for the HONEST leaf
        sth: log.signed_tree_head(&signer),
    };
    print!("[keyserver compromis] forge un reçu pour le build fantôme.\n            ");
    match verify_receipt(&forged, &nonce, &verifier, &anchor) {
        Ok(()) => println!("[client] ⚠️  accepté à tort — BUG"),
        Err(e) => println!("[client] reçu rejeté ({e:?}) → ❌ ATTAQUE DÉTECTÉE"),
    }

    // ---------------- Scenario 3: history cannot be rewritten ----------------
    println!("\n--- Scénario 3 : l'historique ne peut pas être réécrit (append-only) ---");
    let root_before = log.root(); // log currently holds only the honest build (size 1)
    let size_before = log.len();
    // the log grows: two more honest builds get published
    log.append(&measurement_of("v1.1", b"<loader 1.1>"));
    log.append(&measurement_of("v1.2", b"<loader 1.2>"));
    let sth_after = log.signed_tree_head(&signer);
    let cproof = log.consistency_proof(size_before).unwrap();
    print!(
        "[client] log {} → {} : preuve de consistance ({} hash). ",
        size_before,
        sth_after.tree_size,
        cproof.path.len()
    );
    if verify_consistency(&cproof, &root_before, &sth_after.root) {
        println!("✅ append-only prouvé (l'ancien STH est un préfixe du nouveau)");
    } else {
        println!("❌ (BUG)");
    }
    // a provider that secretly rewrote the first entry produces a different old root
    let mut forked = TransparencyLog::new();
    forked.append(&measurement_of("v1.0-rewritten", b"<swapped loader>"));
    print!("[client] même preuve, mais racine historique réécrite en douce : ");
    if verify_consistency(&cproof, &forked.root(), &sth_after.root) {
        println!("⚠️  acceptée — BUG");
    } else {
        println!("❌ REJETÉE → réécriture d'historique détectée");
    }

    println!(
        "\nRésumé : le client refuse un loader que l'attestation classique seule aurait accepté.\n\
         Ce que cette démo prouve : la NON-ÉQUIVOCATION (un build doit être publiquement loggé\n\
         pour qu'un reçu vérifiable existe), l'APPEND-ONLY (historique non réécrit),\n\
         et un canal de session HNDL-safe (X-Wing). Reste : co-signature de témoins (M4)\n\
         et vérifieur WASM (M3)."
    );
}
