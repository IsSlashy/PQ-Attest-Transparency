//! WebAssembly client-side receipt verifier.
//!
//! This is the "user-verifiable in the browser" deliverable: a single exported
//! function that checks a session receipt end to end — binding, STH signature
//! (SLH-DSA), Merkle inclusion, and anchored root — using NO randomness and NO
//! network. It compiles to `wasm32-unknown-unknown` precisely because the verify
//! path of `pqtl-core` is RNG-free (the `rng` feature is off here).

use pqtl_core::slh::SlhVerifier;
use pqtl_core::verify::verify_receipt;
use pqtl_core::{Anchor, Hash, LocalAnchor, MockHardwareRoot, Nonce, Receipt, SignedTreeHead};
use wasm_bindgen::prelude::*;

fn hex32(s: &str) -> Result<Hash, String> {
    let v = hex::decode(s.trim()).map_err(|e| format!("hex: {e}"))?;
    v.try_into().map_err(|_| "expected 32 bytes".to_string())
}

fn verdict(accepted: bool, reason: &str) -> String {
    serde_json::json!({ "accepted": accepted, "reason": reason }).to_string()
}

/// Verify a session receipt entirely client-side.
///
/// - `receipt_json`: the receipt as JSON (as produced by `pqtl-emit`).
/// - `expected_nonce_hex`: the session nonce the client itself chose.
/// - `sth_pubkey_hex`: the log operator's SLH-DSA public key (32 bytes hex).
/// - `hardware_root_pubkey_hex`: the trusted hardware-root (TPM/TDX, here mocked) public key,
///   pinned out of band; the quote's signature is checked against it.
/// - `trusted_root_hex`: the STH root the client obtained out of band (from a
///   witness / gossip / on-chain anchor). The receipt's STH root must match it —
///   this is what defeats a split-view.
///
/// Returns `{"accepted": bool, "reason": string}` as a JSON string.
#[wasm_bindgen]
pub fn verify_receipt_json(
    receipt_json: &str,
    expected_nonce_hex: &str,
    sth_pubkey_hex: &str,
    hardware_root_pubkey_hex: &str,
    trusted_root_hex: &str,
) -> String {
    let receipt: Receipt = match serde_json::from_str(receipt_json) {
        Ok(r) => r,
        Err(e) => return verdict(false, &format!("receipt JSON parse error: {e}")),
    };
    let nonce = match hex32(expected_nonce_hex) {
        Ok(h) => Nonce(h),
        Err(e) => return verdict(false, &format!("nonce: {e}")),
    };
    let pubkey = match hex::decode(sth_pubkey_hex.trim()) {
        Ok(b) => b,
        Err(e) => return verdict(false, &format!("pubkey hex: {e}")),
    };
    let verifier = match SlhVerifier::from_bytes(&pubkey) {
        Ok(v) => v,
        Err(e) => return verdict(false, &format!("pubkey: {e}")),
    };
    let hw_pubkey = match hex::decode(hardware_root_pubkey_hex.trim()) {
        Ok(b) => b,
        Err(e) => return verdict(false, &format!("hardware-root hex: {e}")),
    };
    let quote_verifier = match MockHardwareRoot::from_bytes(&hw_pubkey) {
        Ok(q) => q,
        Err(e) => return verdict(false, &format!("hardware-root key: {e}")),
    };
    let trusted_root = match hex32(trusted_root_hex) {
        Ok(h) => h,
        Err(e) => return verdict(false, &format!("trusted root: {e}")),
    };

    // Seed the anchor with the independently-obtained trusted root: the receipt's
    // STH root must equal it, or verification fails with NotAnchored (split-view).
    let mut anchor = LocalAnchor::default();
    anchor.anchor(&SignedTreeHead {
        tree_size: 0,
        root: trusted_root,
        signature: Vec::new(),
    });

    match verify_receipt(&receipt, &nonce, &quote_verifier, &verifier, &anchor) {
        Ok(()) => verdict(
            true,
            "quote signature + binding + STH signature (SLH-DSA) + Merkle inclusion + anchored root all verified",
        ),
        Err(e) => verdict(false, &format!("{e:?}")),
    }
}
