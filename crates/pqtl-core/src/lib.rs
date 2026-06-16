//! pqtl-core — types, trust-boundary traits, a transparency log, and the
//! client-side receipt verifier for a post-quantum transparency layer over
//! confidential inference.
//!
//! # M0 status: PLACEHOLDER CRYPTO
//! Every cryptographic operation here is a SHA-256 stand-in. There is **no real
//! post-quantum primitive yet** — this milestone proves the end-to-end ✅/❌
//! wiring (binding → inclusion → signature → anchor). Real primitives land later:
//! - M1: append-only Merkle log + STH signed with **SLH-DSA** (FIPS 205) via an
//!   audited crate (see DECISIONS.md ADR-003/005).
//! - M2: session binding with a **hybrid X25519 + ML-KEM-768** KEM.
//!
//! Design rule (DECISIONS.md): every trust boundary is a trait with a mock impl
//! and a documented real path — so the simulated parts are explicit and swappable.

use sha2::{Digest, Sha256};

/// 32-byte hash, the universal currency of this crate.
pub type Hash = [u8; 32];

/// Domain separators — fixed tags prevent cross-protocol hash collisions.
/// (Protocol-01's TS binding omitted these; we add them from the start.)
const DOMAIN_REPORT: &[u8] = b"pqtl:attest:report-v1";
const DOMAIN_STH: &[u8] = b"pqtl:sth-v1";
const DOMAIN_LEAF: &[u8] = &[0x00];
const DOMAIN_NODE: &[u8] = &[0x01];

/// SHA-256 over the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

// ----------------------------------------------------------------------------
// Core types
// ----------------------------------------------------------------------------

/// Hash of a loader build — what gets attested and logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurement(pub Hash);

/// Per-session freshness value chosen by the client (anti-replay).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce(pub Hash);

/// The client's KEM public key. M0: opaque placeholder bytes; M2: hybrid X25519+ML-KEM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemPublicKey(pub Vec<u8>);

/// A (mock) hardware attestation quote. `report_data` binds the session so that
/// a captured ciphertext today cannot be retargeted later (HNDL-safe binding):
/// `report_data = H(DOMAIN ‖ nonce ‖ kem_pubkey ‖ measurement)`.
#[derive(Clone, Debug)]
pub struct Quote {
    pub measurement: Measurement,
    pub report_data: Hash,
}

/// Signed Tree Head: the log operator's commitment to its history at a size.
#[derive(Clone, Debug)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root: Hash,
    pub signature: Vec<u8>,
}

/// A Merkle inclusion proof (RFC 6962 audit path, leaf→root order).
#[derive(Clone, Debug)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub audit_path: Vec<Hash>,
}

/// The client-facing session receipt — the central object of the whole artifact.
#[derive(Clone, Debug)]
pub struct Receipt {
    pub quote: Quote,
    pub nonce: Nonce,
    pub kem_pubkey: KemPublicKey,
    pub inclusion: InclusionProof,
    pub sth: SignedTreeHead,
}

/// `report_data = H(DOMAIN ‖ nonce ‖ kem_pubkey ‖ measurement)`.
pub fn compute_report_data(nonce: &Nonce, kem: &KemPublicKey, m: &Measurement) -> Hash {
    sha256(&[DOMAIN_REPORT, &nonce.0, &kem.0, &m.0])
}

/// Canonical bytes an STH commits to when signed.
pub fn sth_signing_bytes(tree_size: u64, root: &Hash) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN_STH.len() + 8 + 32);
    v.extend_from_slice(DOMAIN_STH);
    v.extend_from_slice(&tree_size.to_be_bytes());
    v.extend_from_slice(root);
    v
}

// ----------------------------------------------------------------------------
// Trust-boundary traits (each: a mock now + a documented real path)
// ----------------------------------------------------------------------------

/// Produces an attestation quote. M0: [`MockQuoteProvider`]. Real path: TDX/TPM quote.
pub trait QuoteProvider {
    fn quote(&self, nonce: &Nonce, kem_pubkey: &KemPublicKey, measurement: &Measurement) -> Quote;
}

/// Signs / verifies the Signed Tree Head. M0: [`PlaceholderSigner`] (a keyed SHA-256
/// tag — NOT a signature). Real path (M1): SLH-DSA (FIPS 205) via an audited crate;
/// the client then holds only the public verifying key.
pub trait SthSigner {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;
}

/// Makes the log's history non-equivocal (anti split-view). M0: [`LocalAnchor`];
/// Web2 core (M4): `WitnessAnchor` (independent witness co-signing); optional
/// stronger path (M5): `ChainAnchor` (on-chain root). See DECISIONS.md ADR-004.
pub trait Anchor {
    fn anchor(&mut self, sth: &SignedTreeHead);
    fn is_anchored(&self, sth: &SignedTreeHead) -> bool;
}

// ----------------------------------------------------------------------------
// M0 placeholder implementations
// ----------------------------------------------------------------------------

/// Stand-in for a real TDX/TPM quote: just computes the binding honestly.
pub struct MockQuoteProvider;
impl QuoteProvider for MockQuoteProvider {
    fn quote(&self, nonce: &Nonce, kem: &KemPublicKey, m: &Measurement) -> Quote {
        Quote {
            measurement: m.clone(),
            report_data: compute_report_data(nonce, kem, m),
        }
    }
}

/// PLACEHOLDER signer: `sig = H("pqtl:placeholder-sig" ‖ key ‖ msg)`. This is a
/// keyed tag standing in for SLH-DSA — it is symmetric (sign==verify key) and is
/// **not** post-quantum and **not** a signature. Replaced wholesale in M1.
pub struct PlaceholderSigner {
    key: Hash,
}
impl PlaceholderSigner {
    pub fn new(seed: &[u8]) -> Self {
        Self {
            key: sha256(&[b"pqtl:placeholder-seed", seed]),
        }
    }
}
impl SthSigner for PlaceholderSigner {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        sha256(&[b"pqtl:placeholder-sig", &self.key, msg]).to_vec()
    }
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        // constant-ish comparison is irrelevant for a placeholder; M1 uses real verify.
        self.sign(msg) == sig
    }
}

/// In-memory anchor: records the set of roots it has witnessed.
#[derive(Default)]
pub struct LocalAnchor {
    roots: std::collections::HashSet<Hash>,
}
impl Anchor for LocalAnchor {
    fn anchor(&mut self, sth: &SignedTreeHead) {
        self.roots.insert(sth.root);
    }
    fn is_anchored(&self, sth: &SignedTreeHead) -> bool {
        self.roots.contains(&sth.root)
    }
}

// ----------------------------------------------------------------------------
// The transparency log
// ----------------------------------------------------------------------------

pub mod log {
    //! Append-only Merkle log (RFC 6962 hashing, with leaf/node domain separation).
    //!
    //! M0: rebuilds the tree from stored leaf hashes on each query (O(n) per proof) —
    //! correct but not incremental. M1 ports Protocol-01's `filled_subtrees` for O(log n)
    //! appends and adds RFC 6962 consistency proofs (neither exists in p01 today).
    use super::*;

    pub fn leaf_hash(m: &Measurement) -> Hash {
        sha256(&[DOMAIN_LEAF, &m.0])
    }
    pub fn node_hash(l: &Hash, r: &Hash) -> Hash {
        sha256(&[DOMAIN_NODE, l, r])
    }

    /// Largest power of two strictly less than `n` (requires `n >= 2`).
    fn split(n: usize) -> usize {
        let mut k = 1;
        while k << 1 < n {
            k <<= 1;
        }
        k
    }

    /// RFC 6962 Merkle Tree Hash over a slice of leaf hashes.
    fn mth(d: &[Hash]) -> Hash {
        match d.len() {
            0 => sha256(&[b"pqtl:empty-tree"]),
            1 => d[0],
            n => {
                let k = split(n);
                node_hash(&mth(&d[..k]), &mth(&d[k..]))
            }
        }
    }

    /// RFC 6962 audit path for leaf `m` within `d` (leaf→root order).
    fn path(m: usize, d: &[Hash]) -> Vec<Hash> {
        let n = d.len();
        if n == 1 {
            return vec![];
        }
        let k = split(n);
        if m < k {
            let mut p = path(m, &d[..k]);
            p.push(mth(&d[k..]));
            p
        } else {
            let mut p = path(m - k, &d[k..]);
            p.push(mth(&d[..k]));
            p
        }
    }

    /// An append-only log of measurements.
    #[derive(Default)]
    pub struct TransparencyLog {
        leaves: Vec<Hash>,
    }

    impl TransparencyLog {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn len(&self) -> u64 {
            self.leaves.len() as u64
        }
        pub fn is_empty(&self) -> bool {
            self.leaves.is_empty()
        }

        /// Append a measurement; returns its leaf index.
        pub fn append(&mut self, m: &Measurement) -> u64 {
            let idx = self.leaves.len() as u64;
            self.leaves.push(leaf_hash(m));
            idx
        }

        /// Index of a measurement if present (first occurrence).
        pub fn find(&self, m: &Measurement) -> Option<u64> {
            let lh = leaf_hash(m);
            self.leaves.iter().position(|x| *x == lh).map(|p| p as u64)
        }

        /// Current Merkle root.
        pub fn root(&self) -> Hash {
            mth(&self.leaves)
        }

        /// Inclusion proof for the leaf at `index`, or `None` if out of range.
        pub fn inclusion_proof(&self, index: u64) -> Option<InclusionProof> {
            let n = self.leaves.len();
            if index as usize >= n {
                return None;
            }
            Some(InclusionProof {
                leaf_index: index,
                tree_size: n as u64,
                audit_path: path(index as usize, &self.leaves),
            })
        }

        /// Produce a Signed Tree Head at the current size.
        pub fn signed_tree_head(&self, signer: &dyn SthSigner) -> SignedTreeHead {
            let root = self.root();
            let size = self.len();
            let signature = signer.sign(&sth_signing_bytes(size, &root));
            SignedTreeHead {
                tree_size: size,
                root,
                signature,
            }
        }
    }

    /// Verify an inclusion proof against `root` (RFC 6962 index-bit reconstruction).
    pub fn verify_inclusion(leaf: &Measurement, proof: &InclusionProof, root: &Hash) -> bool {
        let index = proof.leaf_index;
        let size = proof.tree_size;
        if index >= size {
            return false;
        }
        let inner = (64 - (index ^ (size - 1)).leading_zeros()) as usize;
        let border = (index >> inner).count_ones() as usize;
        if proof.audit_path.len() != inner + border {
            return false;
        }
        let mut res = leaf_hash(leaf);
        for (i, sib) in proof.audit_path.iter().enumerate().take(inner) {
            if (index >> i) & 1 == 0 {
                res = node_hash(&res, sib);
            } else {
                res = node_hash(sib, &res);
            }
        }
        for sib in proof.audit_path.iter().skip(inner) {
            res = node_hash(sib, &res);
        }
        res == *root
    }
}

// ----------------------------------------------------------------------------
// The client-side receipt verifier — THE deliverable
// ----------------------------------------------------------------------------

pub mod verify {
    //! Given a session receipt, decide — entirely on the client side — whether the
    //! session ran on a publicly-logged build. This crate is what compiles to WASM
    //! in M3 so an end user can verify in the browser.
    use super::log::verify_inclusion;
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    pub enum VerifyError {
        /// report_data does not bind our nonce, the kem key and the measurement.
        BindingMismatch,
        /// The STH signature does not verify.
        SthSignatureInvalid,
        /// The attested measurement is not proven to be in the signed root.
        InclusionInvalid,
        /// The signed root was never witnessed/anchored (possible split-view).
        NotAnchored,
    }

    /// The full client check. Order matters: cheapest / most-specific first.
    pub fn verify_receipt(
        r: &Receipt,
        expected_nonce: &Nonce,
        signer: &dyn SthSigner,
        anchor: &dyn Anchor,
    ) -> Result<(), VerifyError> {
        // 1. Binding: the quote must commit to OUR nonce, this kem key, this measurement.
        let expected = compute_report_data(expected_nonce, &r.kem_pubkey, &r.quote.measurement);
        if r.nonce != *expected_nonce || r.quote.report_data != expected {
            return Err(VerifyError::BindingMismatch);
        }
        // 2. The log operator really signed this (size, root).
        let bytes = sth_signing_bytes(r.sth.tree_size, &r.sth.root);
        if !signer.verify(&bytes, &r.sth.signature) {
            return Err(VerifyError::SthSignatureInvalid);
        }
        // 3. The attested measurement is included in that signed root.
        if !verify_inclusion(&r.quote.measurement, &r.inclusion, &r.sth.root) {
            return Err(VerifyError::InclusionInvalid);
        }
        // 4. Non-equivocation: the signed root is one the witnesses/anchor saw.
        if !anchor.is_anchored(&r.sth) {
            return Err(VerifyError::NotAnchored);
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::log::{verify_inclusion, TransparencyLog};
    use super::*;

    fn m(tag: &str) -> Measurement {
        Measurement(sha256(&[b"build", tag.as_bytes()]))
    }

    #[test]
    fn inclusion_proofs_validate_for_all_sizes() {
        for n in 1u64..=33 {
            let mut log = TransparencyLog::new();
            for i in 0..n {
                log.append(&m(&format!("leaf-{i}")));
            }
            let root = log.root();
            for i in 0..n {
                let proof = log.inclusion_proof(i).expect("proof exists");
                assert!(
                    verify_inclusion(&m(&format!("leaf-{i}")), &proof, &root),
                    "n={n} i={i} should verify"
                );
            }
        }
    }

    #[test]
    fn wrong_leaf_fails_inclusion() {
        let mut log = TransparencyLog::new();
        log.append(&m("a"));
        log.append(&m("b"));
        let root = log.root();
        let proof = log.inclusion_proof(0).unwrap();
        assert!(!verify_inclusion(&m("b"), &proof, &root));
    }

    #[test]
    fn full_receipt_roundtrip_and_attack() {
        let mut log = TransparencyLog::new();
        let signer = PlaceholderSigner::new(b"op");
        let qp = MockQuoteProvider;
        let mut anchor = LocalAnchor::default();

        let honest = m("honest");
        let idx = log.append(&honest);
        let sth = log.signed_tree_head(&signer);
        anchor.anchor(&sth);

        let nonce = Nonce(sha256(&[b"n1"]));
        let kem = KemPublicKey(b"pk".to_vec());

        let good = Receipt {
            quote: qp.quote(&nonce, &kem, &honest),
            nonce: nonce.clone(),
            kem_pubkey: kem.clone(),
            inclusion: log.inclusion_proof(idx).unwrap(),
            sth: log.signed_tree_head(&signer),
        };
        assert!(verify::verify_receipt(&good, &nonce, &signer, &anchor).is_ok());

        // Ghost build, never logged: forge a receipt reusing the honest inclusion proof.
        let ghost = m("ghost");
        let forged = Receipt {
            quote: qp.quote(&nonce, &kem, &ghost),
            nonce: nonce.clone(),
            kem_pubkey: kem.clone(),
            inclusion: log.inclusion_proof(idx).unwrap(),
            sth: log.signed_tree_head(&signer),
        };
        assert_eq!(
            verify::verify_receipt(&forged, &nonce, &signer, &anchor),
            Err(verify::VerifyError::InclusionInvalid)
        );
    }
}
