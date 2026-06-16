//! WebAssembly client-side receipt verifier.
//!
//! This is the "user-verifiable in the browser" deliverable: a single exported
//! function that checks a session receipt end to end — binding, STH signature
//! (SLH-DSA), Merkle inclusion, and anchored root — using NO randomness and NO
//! network. It compiles to `wasm32-unknown-unknown` precisely because the verify
//! path of `pqtl-core` is RNG-free (the `rng` feature is off here).

use pqtl_core::slh::SlhVerifier;
use pqtl_core::verify::verify_receipt;
use pqtl_core::witness::WitnessAnchor;
use pqtl_core::{
    Anchor, CosignedSth, Hash, LocalAnchor, MockHardwareRoot, Nonce, Receipt, SignedTreeHead,
};
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

/// Verify a receipt AND the witness quorum that anchors its STH — the full client check the
/// shipped browser deliverable should run. Instead of trusting a supplied root, the client
/// verifies that a threshold of its OWN pinned witnesses cosigned the receipt's STH (and that
/// the quorum does not equivocate).
///
/// - `cosigned_sth_json`: a `CosignedSth` = the receipt's STH + the witness cosignatures.
/// - `witnesses_json`: `[{ "id": u32, "pubkey_hex": "<SLH-DSA pubkey hex>" }, ...]` — the
///   witness set the client pins out of band (NOT obtained from the provider).
/// - `threshold`: how many DISTINCT trusted witnesses must have cosigned.
#[wasm_bindgen]
pub fn verify_receipt_full(
    receipt_json: &str,
    expected_nonce_hex: &str,
    sth_pubkey_hex: &str,
    hardware_root_pubkey_hex: &str,
    cosigned_sth_json: &str,
    witnesses_json: &str,
    threshold: u32,
) -> String {
    let receipt: Receipt = match serde_json::from_str(receipt_json) {
        Ok(r) => r,
        Err(e) => return verdict(false, &format!("receipt JSON: {e}")),
    };
    let cosigned: CosignedSth = match serde_json::from_str(cosigned_sth_json) {
        Ok(c) => c,
        Err(e) => return verdict(false, &format!("cosigned-STH JSON: {e}")),
    };
    let nonce = match hex32(expected_nonce_hex) {
        Ok(h) => Nonce(h),
        Err(e) => return verdict(false, &format!("nonce: {e}")),
    };
    let verifier = match hex::decode(sth_pubkey_hex.trim())
        .ok()
        .and_then(|b| SlhVerifier::from_bytes(&b).ok())
    {
        Some(v) => v,
        None => return verdict(false, "bad STH public key"),
    };
    let quote_verifier = match hex::decode(hardware_root_pubkey_hex.trim())
        .ok()
        .and_then(|b| MockHardwareRoot::from_bytes(&b).ok())
    {
        Some(q) => q,
        None => return verdict(false, "bad hardware-root public key"),
    };

    // Build the client's pinned witness set.
    let witnesses_val: serde_json::Value = match serde_json::from_str(witnesses_json) {
        Ok(v) => v,
        Err(e) => return verdict(false, &format!("witnesses JSON: {e}")),
    };
    let arr = match witnesses_val.as_array() {
        Some(a) => a,
        None => return verdict(false, "witnesses must be a JSON array"),
    };
    let mut trusted = Vec::with_capacity(arr.len());
    for w in arr {
        let id = match w.get("id").and_then(|v| v.as_u64()) {
            Some(i) => i as u32,
            None => return verdict(false, "witness missing numeric id"),
        };
        let pk_hex = match w.get("pubkey_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return verdict(false, "witness missing pubkey_hex"),
        };
        let v = match hex::decode(pk_hex.trim())
            .ok()
            .and_then(|b| SlhVerifier::from_bytes(&b).ok())
        {
            Some(v) => v,
            None => return verdict(false, &format!("bad witness pubkey (id {id})")),
        };
        if trusted.iter().any(|(tid, _)| *tid == id) {
            return verdict(false, &format!("duplicate witness id {id} in pinned set"));
        }
        trusted.push((id, v));
    }

    // The cosigned STH must be the receipt's OWN STH (size + root), else the quorum is for a
    // different tree and would not legitimately anchor this receipt.
    if cosigned.sth.tree_size != receipt.sth.tree_size || cosigned.sth.root != receipt.sth.root {
        return verdict(false, "cosigned STH does not match the receipt's STH");
    }

    if threshold == 0 {
        return verdict(false, "threshold must be >= 1");
    }
    // Verify the witness quorum CLIENT-SIDE; only then is the root anchored.
    let mut anchor = WitnessAnchor::new(trusted, threshold as usize);
    if !anchor.ingest(&cosigned, None) {
        return verdict(false, "witness quorum not reached (or equivocation detected)");
    }

    match verify_receipt(&receipt, &nonce, &quote_verifier, &verifier, &anchor) {
        Ok(()) => verdict(
            true,
            "quote + binding + STH signature + Merkle inclusion + WITNESS-QUORUM-anchored root all verified",
        ),
        Err(e) => verdict(false, &format!("{e:?}")),
    }
}
