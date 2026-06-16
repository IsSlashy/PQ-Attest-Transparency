//! Micro-benchmarks: "how much does post-quantum cost?" — sizes and client-side
//! verification latencies. Run in RELEASE (signing is meaningless in debug):
//!   cargo run --release -p pqtl-cli --bin pqtl-bench
//!
//! Latencies are machine-dependent; the point is the ORDER OF MAGNITUDE and the
//! ratio between operations (e.g. SLH-DSA sign vs verify, gen O(n) vs verify O(log n)).

use pqtl_core::kem::{self, ClientKeypair};
use pqtl_core::log::{verify_consistency, verify_inclusion, TransparencyLog};
use pqtl_core::slh::SlhSigner;
use pqtl_core::verify::verify_receipt;
use pqtl_core::witness::{Witness, WitnessAnchor};
use pqtl_core::*;
use std::hint::black_box;
use std::time::Instant;

fn bench<F: FnMut()>(iters: u32, mut f: F) -> (f64, f64) {
    for _ in 0..3 {
        f();
    } // warmup
    let mut samples = Vec::with_capacity(iters as usize);
    for _ in 0..iters {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_secs_f64() * 1e3); // ms
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = samples[samples.len() / 2];
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    (median, mean)
}

fn row<F: FnMut()>(name: &str, iters: u32, f: F) {
    let (median, mean) = bench(iters, f);
    println!("| {name} | {median:.4} | {mean:.4} | {iters} |");
}

fn leaf(i: usize) -> Measurement {
    Measurement(sha256(&[b"leaf", &(i as u64).to_le_bytes()]))
}

fn receipt_wire_bytes(r: &Receipt) -> usize {
    32 // measurement
        + 32 // report_data
        + 32 // nonce
        + r.kem_pubkey.0.len()
        + r.kem_ciphertext.len()
        + 16 + r.inclusion.audit_path.len() * 32 // inclusion (indices + path)
        + 8 + 32 + r.sth.signature.len() // sth (size + root + signature)
}

fn main() {
    println!("# PQ-Attest-Transparency — micro-benchmarks (release)\n");

    // ---- Latencies ----
    println!("## Latencies (median over N iters, machine-dependent)\n");
    println!("| Operation | median (ms) | mean (ms) | iters |");
    println!("|---|--:|--:|--:|");

    row("SLH-DSA-128s keygen", 20, || {
        black_box(SlhSigner::generate().unwrap());
    });
    let signer = SlhSigner::generate().unwrap();
    let verifier = signer.verifier();
    let msg = sha256(&[b"bench-msg"]).to_vec();
    row("SLH-DSA-128s sign", 20, || {
        black_box(signer.sign(black_box(&msg)));
    });
    let sig = signer.sign(&msg);
    row("SLH-DSA-128s verify", 100, || {
        black_box(verifier.verify(black_box(&msg), black_box(&sig)));
    });

    row("X-Wing keygen", 200, || {
        black_box(ClientKeypair::generate());
    });
    let client = ClientKeypair::generate();
    let pk = client.public_key();
    row("X-Wing encapsulate", 500, || {
        black_box(kem::encapsulate(black_box(&pk.0)).unwrap());
    });
    let (ct, _) = kem::encapsulate(&pk.0).unwrap();
    row("X-Wing decapsulate", 500, || {
        black_box(client.decapsulate(black_box(&ct)).unwrap());
    });

    for &n in &[1024usize, 65536usize] {
        let mut log = TransparencyLog::new();
        for i in 0..n {
            log.append(&leaf(i));
        }
        let root = log.root();
        let idx = (n / 2) as u64;
        row(&format!("Merkle inclusion gen (n={n})"), 50, || {
            black_box(log.inclusion_proof(black_box(idx)));
        });
        let proof = log.inclusion_proof(idx).unwrap();
        let lf = leaf(n / 2);
        row(&format!("Merkle inclusion verify (n={n})"), 2000, || {
            black_box(verify_inclusion(black_box(&lf), black_box(&proof), black_box(&root)));
        });
        let cproof = log.consistency_proof((n / 2) as u64).unwrap();
        let mut half = TransparencyLog::new();
        for i in 0..n / 2 {
            half.append(&leaf(i));
        }
        let root_half = half.root();
        row(&format!("Consistency verify (n={}->{})", n / 2, n), 2000, || {
            black_box(verify_consistency(
                black_box(&cproof),
                black_box(&root_half),
                black_box(&root),
            ));
        });
    }

    // A full client receipt verification (binding + STH sig + inclusion + anchor).
    let mut log = TransparencyLog::new();
    let honest = Measurement(sha256(&[b"loader-build"]));
    let hidx = log.append(&honest);
    let sth = log.signed_tree_head(&signer);
    let nonce = Nonce(sha256(&[b"nonce"]));
    let (rct, _) = kem::encapsulate(&pk.0).unwrap();
    let qp = MockQuoteProvider;
    let receipt = Receipt {
        quote: qp.quote(&nonce, &pk, &honest),
        nonce: nonce.clone(),
        kem_pubkey: pk.clone(),
        kem_ciphertext: rct,
        inclusion: log.inclusion_proof(hidx).unwrap(),
        sth: sth.clone(),
    };
    let mut anchor = LocalAnchor::default();
    anchor.anchor(&sth);
    row("full receipt verify (client)", 200, || {
        black_box(
            verify_receipt(
                black_box(&receipt),
                black_box(&nonce),
                black_box(&verifier),
                black_box(&anchor),
            )
            .is_ok(),
        );
    });

    // Witness cosignature verification (one SLH-DSA verify under the hood).
    let mut w = Witness::generate(7);
    let cosig = w.cosign(&sth, None).unwrap();
    let cosigned = CosignedSth {
        sth: sth.clone(),
        cosignatures: vec![cosig],
    };
    row("WitnessAnchor.ingest (1 cosig)", 200, || {
        let mut a = WitnessAnchor::new(vec![(7u32, w.verifier())], 1);
        black_box(a.ingest(black_box(&cosigned)));
    });

    // ---- Sizes ----
    println!("\n## Sizes (bytes)\n");
    println!("| Object | size (B) |");
    println!("|---|--:|");
    println!("| SLH-DSA-128s public key | {} |", signer.public_key_bytes().len());
    println!("| SLH-DSA-128s signature | {} |", sig.len());
    println!("| X-Wing public key | {} |", pk.0.len());
    println!("| X-Wing ciphertext | {} |", ct.len());
    println!("| full session receipt | {} |", receipt_wire_bytes(&receipt));
    println!(
        "| witness cosignature (per witness) | {} |",
        cosigned.cosignatures[0].signature.len()
    );
}
