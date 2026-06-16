//! pqtl-core — types, trust-boundary traits, a transparency log, and the
//! client-side receipt verifier for a post-quantum transparency layer over
//! confidential inference.
//!
//! # Status: M0–M4 complete; the verification path is RNG-free and wasm-ready.
//! Real crypto throughout: SLH-DSA STH signatures ([`slh`]); RFC 6962 Merkle inclusion +
//! consistency proofs ([`log`]); hybrid X25519+ML-KEM-768 session binding ([`kem`]); witness
//! anti-split-view ([`witness`]). Caveats (see `THREAT-MODEL.md`): the hardware attestation
//! quote ([`QuoteProvider`]) is MOCKED and the PQ crates are UNAUDITED. Pending: an incremental
//! O(log n) Merkle log (currently rebuilt O(n) per query).
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
const DOMAIN_QUOTE: &[u8] = b"pqtl:quote-v1";
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Measurement(pub Hash);

/// Per-session freshness value chosen by the client (anti-replay).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Nonce(pub Hash);

/// The client's KEM public key. M0: opaque placeholder bytes; M2: hybrid X25519+ML-KEM.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KemPublicKey(pub Vec<u8>);

/// A (mock) hardware attestation quote. `report_data` binds the session so that
/// a captured ciphertext today cannot be retargeted later (HNDL-safe binding):
/// `report_data = H(DOMAIN ‖ nonce ‖ kem_pubkey ‖ measurement)`.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Quote {
    pub measurement: Measurement,
    pub report_data: Hash,
    /// The hardware root's signature over (measurement ‖ report_data). In a real
    /// deployment this is the TDX/TPM quote signature chaining to a manufacturer key; here
    /// it is signed by a MOCKED hardware root ([`MockQuoteProvider`]). A verifier holding
    /// the trusted root public key checks it via [`QuoteVerifier`] — WITHOUT this check the
    /// binding alone is tautological (a software provider can bind any measurement). See
    /// THREAT-MODEL.md §3.
    pub hardware_sig: Vec<u8>,
}

/// Signed Tree Head: the log operator's commitment to its history at a size.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root: Hash,
    pub signature: Vec<u8>,
}

/// A Merkle inclusion proof (RFC 6962 audit path, leaf→root order).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub audit_path: Vec<Hash>,
}

/// An RFC 6962 consistency proof: proves the size-`first_size` tree is a prefix of
/// the size-`second_size` tree — i.e. the log was only appended to, never rewritten.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConsistencyProof {
    pub first_size: u64,
    pub second_size: u64,
    pub path: Vec<Hash>,
}

/// The client-facing session receipt — the central object of the whole artifact.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Receipt {
    pub quote: Quote,
    pub nonce: Nonce,
    pub kem_pubkey: KemPublicKey,
    /// The keyserver's X-Wing ciphertext (key release). The client decapsulates it
    /// with its secret key to recover the session shared secret (M2).
    pub kem_ciphertext: Vec<u8>,
    pub inclusion: InclusionProof,
    pub sth: SignedTreeHead,
}

/// One witness's cosignature over a Signed Tree Head (M4).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WitnessCosignature {
    pub witness_id: u32,
    pub signature: Vec<u8>,
}

/// An STH plus the independent witness cosignatures that make its root
/// non-equivocal without a blockchain — the Web2 anti-split-view object (M4).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CosignedSth {
    pub sth: SignedTreeHead,
    pub cosignatures: Vec<WitnessCosignature>,
}

/// `report_data = H(DOMAIN ‖ nonce ‖ kem_pubkey ‖ measurement)`.
pub fn compute_report_data(nonce: &Nonce, kem: &KemPublicKey, m: &Measurement) -> Hash {
    sha256(&[DOMAIN_REPORT, &nonce.0, &kem.0, &m.0])
}

/// Canonical bytes the hardware root signs in a quote: it attests `(measurement, report_data)`.
pub fn quote_signing_bytes(measurement: &Measurement, report_data: &Hash) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN_QUOTE.len() + 32 + 32);
    v.extend_from_slice(DOMAIN_QUOTE);
    v.extend_from_slice(&measurement.0);
    v.extend_from_slice(report_data);
    v
}

/// Canonical bytes an STH commits to when signed.
pub fn sth_signing_bytes(tree_size: u64, root: &Hash) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN_STH.len() + 8 + 32);
    v.extend_from_slice(DOMAIN_STH);
    v.extend_from_slice(&tree_size.to_be_bytes());
    v.extend_from_slice(root);
    v
}

const DOMAIN_COSIG: &[u8] = b"pqtl:witness-cosig-v1";

/// Canonical bytes a witness cosigns — domain-separated from the operator's STH
/// signature so a witness cosignature can never be replayed as an operator signature.
pub fn cosignature_bytes(tree_size: u64, root: &Hash) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN_COSIG.len() + 8 + 32);
    v.extend_from_slice(DOMAIN_COSIG);
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

/// Verifies that an attestation quote was signed by the trusted hardware root. M0:
/// [`MockHardwareRoot`]. Real path: verify the TDX/TPM quote signature against a manufacturer
/// cert chain. This is RNG-free (wasm-ok). WITHOUT this check, `verify_receipt`'s binding step
/// is tautological — a software quote provider can bind any measurement (THREAT-MODEL.md §3).
pub trait QuoteVerifier {
    fn verify_quote(&self, quote: &Quote) -> bool;
}

/// Verifies a Signed Tree Head signature — the ONLY capability the client needs,
/// since it holds just the log operator's public key. M0: [`PlaceholderSigner`];
/// M1: [`slh::SlhVerifier`] (SLH-DSA / FIPS 205). Verification needs no RNG, so a
/// `SthVerifier` compiles cleanly to wasm32 for the M3 browser verifier.
pub trait SthVerifier {
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;
}

/// Signs the Signed Tree Head (log-operator side; holds the secret key).
/// M0: [`PlaceholderSigner`]; M1: [`slh::SlhSigner`].
pub trait SthSigner {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
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

/// Stand-in for a TDX/TPM quote provider. Holds a MOCKED hardware-root signing key and signs
/// each quote with it, modeling a hardware root that a (compromised) software provider does not
/// control. Requires the `rng` feature. The honest binding is computed; the signature is what
/// a real attacker cannot forge without the hardware key.
#[cfg(feature = "rng")]
pub struct MockQuoteProvider {
    root: slh::SlhSigner,
}

#[cfg(feature = "rng")]
impl MockQuoteProvider {
    pub fn generate() -> Self {
        Self {
            root: slh::SlhSigner::generate().expect("hardware-root keygen"),
        }
    }
    /// The trusted hardware-root public key the client pins out of band (like a TPM EK cert).
    pub fn hardware_root_pubkey(&self) -> Vec<u8> {
        self.root.public_key_bytes()
    }
    /// The matching verifier the client uses to check quotes.
    pub fn verifier(&self) -> MockHardwareRoot {
        MockHardwareRoot::from_bytes(&self.hardware_root_pubkey()).expect("own root pk is valid")
    }
}

#[cfg(feature = "rng")]
impl QuoteProvider for MockQuoteProvider {
    fn quote(&self, nonce: &Nonce, kem: &KemPublicKey, m: &Measurement) -> Quote {
        let report_data = compute_report_data(nonce, kem, m);
        let hardware_sig = self.root.sign(&quote_signing_bytes(m, &report_data));
        Quote {
            measurement: m.clone(),
            report_data,
            hardware_sig,
        }
    }
}

/// Client-side verifier of a mocked hardware-root quote signature (SLH-DSA). RNG-free → wasm-ok.
pub struct MockHardwareRoot {
    root_pk: slh::SlhVerifier,
}

impl MockHardwareRoot {
    pub fn from_bytes(pubkey: &[u8]) -> Result<Self, &'static str> {
        Ok(Self {
            root_pk: slh::SlhVerifier::from_bytes(pubkey)?,
        })
    }
}

impl QuoteVerifier for MockHardwareRoot {
    fn verify_quote(&self, quote: &Quote) -> bool {
        self.root_pk.verify(
            &quote_signing_bytes(&quote.measurement, &quote.report_data),
            &quote.hardware_sig,
        )
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
}
impl SthVerifier for PlaceholderSigner {
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
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
// Real post-quantum STH signing (M1): SLH-DSA / FIPS 205
// ----------------------------------------------------------------------------

pub mod slh {
    //! STH signing with SLH-DSA (FIPS 205), parameter set **SLH-DSA-SHA2-128s**
    //! (small signatures for an infrequently-signed STH). Replaces the M0 placeholder.
    //!
    //! The log operator holds [`SlhSigner`] (secret key); the client holds only
    //! [`SlhVerifier`] (public key). Verification uses no RNG → clean wasm32 build.
    //! Crate is maintained + NIST-vector-tested but NOT independently audited.
    use super::SthVerifier;
    #[cfg(feature = "rng")]
    use super::SthSigner;
    use fips205::slh_dsa_sha2_128s as pset;
    use fips205::traits::{SerDes, Verifier};
    #[cfg(feature = "rng")]
    use fips205::traits::Signer;

    /// SLH-DSA-SHA2-128s signature length in bytes (7856).
    pub const SIG_LEN: usize = pset::SIG_LEN;
    /// SLH-DSA-SHA2-128s public-key length in bytes (32).
    pub const PK_LEN: usize = pset::PK_LEN;

    /// Client-side verifying key (public only). Available everywhere, including the
    /// `--no-default-features` (verify-only, wasm32) build — it needs no RNG.
    pub struct SlhVerifier {
        pk: pset::PublicKey,
    }

    impl SlhVerifier {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
            let arr: [u8; PK_LEN] = bytes.try_into().map_err(|_| "bad public-key length")?;
            Ok(SlhVerifier {
                pk: pset::PublicKey::try_from_bytes(&arr)?,
            })
        }
    }

    impl SthVerifier for SlhVerifier {
        fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
            let arr: [u8; SIG_LEN] = match sig.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            self.pk.verify(msg, &arr, &[])
        }
    }

    /// Log-operator signing key. Requires the `rng` feature (keygen + hedged signing).
    #[cfg(feature = "rng")]
    pub struct SlhSigner {
        sk: pset::PrivateKey,
        pk_bytes: [u8; PK_LEN],
    }

    #[cfg(feature = "rng")]
    impl SlhSigner {
        /// Generate a fresh keypair (uses the OS RNG via `getrandom`).
        pub fn generate() -> Result<Self, &'static str> {
            let (pk, sk) = pset::try_keygen()?;
            Ok(Self {
                sk,
                pk_bytes: pk.into_bytes(),
            })
        }
        /// The matching public verifier the client would receive out of band.
        pub fn verifier(&self) -> SlhVerifier {
            SlhVerifier::from_bytes(&self.pk_bytes).expect("own public key is valid")
        }
        pub fn public_key_bytes(&self) -> Vec<u8> {
            self.pk_bytes.to_vec()
        }
    }

    #[cfg(feature = "rng")]
    impl SthSigner for SlhSigner {
        fn sign(&self, msg: &[u8]) -> Vec<u8> {
            // empty context, hedged (randomized) signing per FIPS 205 recommendation.
            self.sk
                .try_sign(msg, &[], true)
                .expect("slh-dsa signing")
                .to_vec()
        }
    }
}

// ----------------------------------------------------------------------------
// Real HNDL-safe session binding (M2): hybrid X25519 + ML-KEM-768 (X-Wing)
// ----------------------------------------------------------------------------

pub mod kem {
    //! Session key establishment with **X-Wing** (hybrid X25519 + ML-KEM-768,
    //! draft-connolly-cfrg-xwing-kem). HNDL-safe: recovering the session key requires
    //! breaking BOTH X25519 *and* ML-KEM-768, so a ciphertext harvested today is not
    //! decryptable by a future quantum adversary.
    //!
    //! Flow: the client generates a keypair and puts its public key in the attestation
    //! binding (`report_data`). The keyserver encapsulates against it, yielding a
    //! ciphertext (the key release) and a shared secret; the client decapsulates the
    //! ciphertext to recover the same secret. Both derive the session key with HKDF,
    //! transcript-bound to the attested measurement. Crate maintained, NOT audited.
    use super::{sha256, Hash, Measurement, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    #[cfg(feature = "rng")]
    use super::KemPublicKey;
    #[cfg(feature = "rng")]
    use x_wing::{
        Ciphertext, Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, KeyExport, Kem,
        SharedKey, XWingKem,
    };

    /// X-Wing ciphertext length in bytes (1120).
    pub const CIPHERTEXT_LEN: usize = x_wing::CIPHERTEXT_SIZE;
    /// X-Wing public (encapsulation) key length in bytes (1216).
    pub const PUBLIC_KEY_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;

    #[cfg(feature = "rng")]
    fn shared_to_bytes(ss: &SharedKey) -> [u8; 32] {
        let mut b = [0u8; 32];
        b.copy_from_slice(&ss[..]);
        b
    }
    #[cfg(feature = "rng")]
    fn ciphertext_from_bytes(bytes: &[u8]) -> Option<Ciphertext> {
        if bytes.len() != CIPHERTEXT_LEN {
            return None;
        }
        let mut ct = Ciphertext::default();
        ct.copy_from_slice(bytes);
        Some(ct)
    }

    /// Client-side X-Wing keypair. The secret never leaves the client.
    /// Requires the `rng` feature (keygen). Decapsulation itself uses no RNG.
    #[cfg(feature = "rng")]
    pub struct ClientKeypair {
        sk: DecapsulationKey,
        pk_bytes: Vec<u8>,
    }

    #[cfg(feature = "rng")]
    impl ClientKeypair {
        pub fn generate() -> Self {
            let (sk, pk) = XWingKem::generate_keypair();
            ClientKeypair {
                sk,
                pk_bytes: pk.to_bytes().to_vec(),
            }
        }
        /// The public key, ready to embed in the attestation binding.
        pub fn public_key(&self) -> KemPublicKey {
            KemPublicKey(self.pk_bytes.clone())
        }
        /// Decapsulate the keyserver's ciphertext into the 32-byte shared secret.
        pub fn decapsulate(&self, ciphertext: &[u8]) -> Option<[u8; 32]> {
            let ct = ciphertext_from_bytes(ciphertext)?;
            Some(shared_to_bytes(&self.sk.decapsulate(&ct)))
        }
    }

    /// Keyserver side: encapsulate against a client public key.
    /// Returns `(ciphertext_bytes, shared_secret)`, or `None` if the key is malformed.
    #[cfg(feature = "rng")]
    pub fn encapsulate(client_pubkey: &[u8]) -> Option<(Vec<u8>, [u8; 32])> {
        let ek = EncapsulationKey::try_from(client_pubkey).ok()?;
        let (ct, ss) = ek.encapsulate();
        Some((ct.to_vec(), shared_to_bytes(&ss)))
    }

    /// HKDF-SHA256 session key, transcript-bound to the attested context:
    /// `HKDF(ikm = xwing_ss, info = H("pqtl:session-v1" ‖ nonce ‖ ciphertext ‖ measurement))`.
    pub fn derive_session_key(
        shared_secret: &[u8; 32],
        nonce: &Nonce,
        ciphertext: &[u8],
        measurement: &Measurement,
    ) -> Hash {
        let transcript = sha256(&[b"pqtl:session-v1", &nonce.0, ciphertext, &measurement.0]);
        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut okm = [0u8; 32];
        hk.expand(&transcript, &mut okm)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        okm
    }
}

// ----------------------------------------------------------------------------
// Anti-split-view by witness co-signing (M4): the Web2 trusted-root source
// ----------------------------------------------------------------------------

pub mod witness {
    //! Independent witnesses make a log's STH root non-equivocal *without a blockchain*.
    //! A witness cosigns an STH only after checking (via an RFC 6962 consistency proof)
    //! that the new tree extends the one it last saw — so an honest witness refuses to
    //! cosign a forked/rewritten history. A client trusts a root only if a quorum of the
    //! witnesses it knows have cosigned it.
    //!
    //! The verifier side ([`WitnessAnchor`]) uses no RNG, so it compiles to wasm32 too.
    use super::log::verify_consistency;
    use super::slh::SlhVerifier;
    use super::{
        cosignature_bytes, Anchor, ConsistencyProof, CosignedSth, Hash, SignedTreeHead,
        SthVerifier, WitnessCosignature,
    };
    use std::collections::{HashMap, HashSet};

    /// A witness: holds its own signing key and the last STH it attested to.
    /// Requires the `rng` feature (keygen + signing).
    #[cfg(feature = "rng")]
    pub struct Witness {
        id: u32,
        signer: super::slh::SlhSigner,
        last: Option<(u64, Hash)>,
    }

    #[cfg(feature = "rng")]
    impl Witness {
        pub fn generate(id: u32) -> Self {
            Self {
                id,
                signer: super::slh::SlhSigner::generate().expect("witness keygen"),
                last: None,
            }
        }
        pub fn id(&self) -> u32 {
            self.id
        }
        pub fn public_key_bytes(&self) -> Vec<u8> {
            self.signer.public_key_bytes()
        }
        pub fn verifier(&self) -> SlhVerifier {
            self.signer.verifier()
        }

        /// Cosign an STH. If this witness has cosigned before, it REFUSES unless the
        /// supplied consistency proof shows the new tree extends the one it last saw.
        /// This is what makes an honest witness reject a forked/rewritten history.
        pub fn cosign(
            &mut self,
            sth: &SignedTreeHead,
            consistency: Option<&ConsistencyProof>,
        ) -> Option<WitnessCosignature> {
            if let Some((last_size, last_root)) = self.last {
                let proof = consistency?;
                if proof.first_size != last_size || proof.second_size != sth.tree_size {
                    return None;
                }
                if !verify_consistency(proof, &last_root, &sth.root) {
                    return None; // fork / rewrite → refuse to cosign
                }
            }
            use super::SthSigner;
            let signature = self.signer.sign(&cosignature_bytes(sth.tree_size, &sth.root));
            self.last = Some((sth.tree_size, sth.root));
            Some(WitnessCosignature {
                witness_id: self.id,
                signature,
            })
        }
    }

    /// Client-side anchor: trusts a `(tree_size, root)` only once a quorum of known witnesses
    /// has validly cosigned it AND it is consistent with what the client already trusts. RNG-free
    /// → usable in the wasm verifier.
    pub struct WitnessAnchor {
        trusted: Vec<(u32, SlhVerifier)>,
        threshold: usize,
        accepted: HashSet<(u64, Hash)>,
        by_size: HashMap<u64, Hash>,
    }

    impl WitnessAnchor {
        pub fn new(trusted: Vec<(u32, SlhVerifier)>, threshold: usize) -> Self {
            Self {
                trusted,
                threshold,
                accepted: HashSet::new(),
                by_size: HashMap::new(),
            }
        }

        /// Accept a cosigned STH's root iff:
        /// (a) a quorum of `threshold` DISTINCT trusted witnesses validly cosigned it;
        /// (b) it does not **equivocate** — no different root is already trusted at this size;
        /// (c) if it grows past the highest size we trust, `consistency` proves the new tree
        ///     extends that trusted root (client-side append-only check, defence-in-depth
        ///     against a colluding quorum that the witness-side check would otherwise miss).
        /// Returns whether the root was accepted.
        pub fn ingest(
            &mut self,
            cosigned: &CosignedSth,
            consistency: Option<&ConsistencyProof>,
        ) -> bool {
            let size = cosigned.sth.tree_size;
            let root = cosigned.sth.root;

            // A zero threshold would "trust" a root with no cosignatures at all — reject it.
            if self.threshold == 0 {
                return false;
            }

            // (a) quorum of distinct, valid cosignatures
            let msg = cosignature_bytes(size, &root);
            let mut seen = HashSet::new();
            for cs in &cosigned.cosignatures {
                if seen.contains(&cs.witness_id) {
                    continue;
                }
                if let Some((_, v)) = self.trusted.iter().find(|(id, _)| *id == cs.witness_id) {
                    if v.verify(&msg, &cs.signature) {
                        seen.insert(cs.witness_id);
                    }
                }
            }
            if seen.len() < self.threshold {
                return false;
            }

            // (b) no same-size equivocation
            if let Some(prev) = self.by_size.get(&size) {
                if *prev != root {
                    return false; // a different root at the same size == split-view
                }
            }

            // (c) append-only across the highest root we already trust
            if let Some((&max_size, &max_root)) = self.by_size.iter().max_by_key(|(s, _)| **s) {
                if size > max_size {
                    let ok = matches!(consistency, Some(p)
                        if p.first_size == max_size
                            && p.second_size == size
                            && verify_consistency(p, &max_root, &root));
                    if !ok {
                        return false;
                    }
                }
            }

            self.by_size.insert(size, root);
            self.accepted.insert((size, root));
            true
        }
    }

    impl Anchor for WitnessAnchor {
        fn anchor(&mut self, _sth: &SignedTreeHead) {
            // No-op by design: a root becomes trusted only through `ingest` (witness
            // cosignatures + consistency), never by bare assertion. See DECISIONS.md ADR-004.
        }
        fn is_anchored(&self, sth: &SignedTreeHead) -> bool {
            self.accepted.contains(&(sth.tree_size, sth.root))
        }
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

    /// RFC 6962 SUBPROOF, the recursive core of a consistency proof.
    fn cons_subproof(m: usize, d: &[Hash], b: bool) -> Vec<Hash> {
        let n = d.len();
        if m == n {
            return if b { vec![] } else { vec![mth(d)] };
        }
        let k = split(n);
        if m <= k {
            let mut p = cons_subproof(m, &d[..k], b);
            p.push(mth(&d[k..]));
            p
        } else {
            let mut p = cons_subproof(m - k, &d[k..], false);
            p.push(mth(&d[..k]));
            p
        }
    }

    // --- shared proof-replay helpers (RFC 6962 / Trillian) ---
    fn bit_len(x: u64) -> usize {
        (64 - x.leading_zeros()) as usize
    }
    /// Chain `seed` up through `proof`, choosing side by the bits of `index`.
    fn chain_inner(seed: Hash, proof: &[Hash], index: u64) -> Hash {
        let mut acc = seed;
        for (i, h) in proof.iter().enumerate() {
            acc = if (index >> i) & 1 == 0 {
                node_hash(&acc, h)
            } else {
                node_hash(h, &acc)
            };
        }
        acc
    }
    /// Like `chain_inner` but only folds the right-side (set-bit) nodes.
    fn chain_inner_right(seed: Hash, proof: &[Hash], index: u64) -> Hash {
        let mut acc = seed;
        for (i, h) in proof.iter().enumerate() {
            if (index >> i) & 1 == 1 {
                acc = node_hash(h, &acc);
            }
        }
        acc
    }
    /// Fold the remaining border nodes (always left siblings).
    fn chain_border_right(seed: Hash, proof: &[Hash]) -> Hash {
        let mut acc = seed;
        for h in proof {
            acc = node_hash(h, &acc);
        }
        acc
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

        /// RFC 6962 consistency proof from `first_size` to the current size.
        pub fn consistency_proof(&self, first_size: u64) -> Option<ConsistencyProof> {
            let n = self.leaves.len() as u64;
            if first_size == 0 || first_size > n {
                return None;
            }
            let path = if first_size == n {
                Vec::new()
            } else {
                cons_subproof(first_size as usize, &self.leaves, true)
            };
            Some(ConsistencyProof {
                first_size,
                second_size: n,
                path,
            })
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

    /// Verify an RFC 6962 consistency proof: that the tree committed by `first_root`
    /// (size `proof.first_size`) is a prefix of the tree committed by `second_root`
    /// (size `proof.second_size`). This is the "history was not rewritten" check.
    pub fn verify_consistency(
        proof: &ConsistencyProof,
        first_root: &Hash,
        second_root: &Hash,
    ) -> bool {
        let m = proof.first_size;
        let n = proof.second_size;
        let path = &proof.path;
        if n < m {
            return false;
        }
        if m == n {
            return path.is_empty() && first_root == second_root;
        }
        if m == 0 {
            // every tree is consistent with the empty tree — but only if first_root really IS
            // the empty-tree root (do not accept an arbitrary claimed root).
            return path.is_empty() && *first_root == mth(&[]);
        }
        // 0 < m < n
        let inner0 = bit_len((m - 1) ^ (n - 1));
        let border = ((m - 1) >> inner0).count_ones() as usize;
        let shift = m.trailing_zeros() as usize;
        if inner0 < shift {
            return false;
        }
        let inner = inner0 - shift;

        // The seed is root1 when m is a power of two, else the first proof element.
        let (seed, start) = if m == (1u64 << shift) {
            (*first_root, 0usize)
        } else if let Some(h) = path.first() {
            (*h, 1usize)
        } else {
            return false;
        };
        if path.len() != start + inner + border {
            return false;
        }
        let rest = &path[start..];
        let mask = (m - 1) >> shift;

        let hash1 = chain_border_right(chain_inner_right(seed, &rest[..inner], mask), &rest[inner..]);
        let hash2 = chain_border_right(chain_inner(seed, &rest[..inner], mask), &rest[inner..]);

        &hash1 == first_root && &hash2 == second_root
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
        /// The attestation quote is not signed by the trusted hardware root.
        QuoteSignatureInvalid,
        /// report_data does not bind our nonce, the kem key and the measurement.
        BindingMismatch,
        /// kem_pubkey / kem_ciphertext have the wrong length.
        MalformedKem,
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
        quote_verifier: &dyn QuoteVerifier,
        verifier: &dyn SthVerifier,
        anchor: &dyn Anchor,
    ) -> Result<(), VerifyError> {
        // 0. The quote must be signed by the TRUSTED hardware root. Without this the binding
        //    check below is tautological — a software provider can bind any measurement.
        if !quote_verifier.verify_quote(&r.quote) {
            return Err(VerifyError::QuoteSignatureInvalid);
        }
        // 1. Binding: the quote must commit to OUR nonce, this kem key, this measurement.
        let expected = compute_report_data(expected_nonce, &r.kem_pubkey, &r.quote.measurement);
        if r.nonce != *expected_nonce || r.quote.report_data != expected {
            return Err(VerifyError::BindingMismatch);
        }
        // 1b. Length-pin the KEM fields. NOTE: a sound HNDL session ALSO requires the client to
        //     actually decapsulate r.kem_ciphertext and derive the session key — that happens at
        //     the application layer, not here (see THREAT-MODEL.md §4.3).
        if r.kem_pubkey.0.len() != kem::PUBLIC_KEY_LEN
            || r.kem_ciphertext.len() != kem::CIPHERTEXT_LEN
        {
            return Err(VerifyError::MalformedKem);
        }
        // 2. The log operator really signed this (size, root) — checked with the public key only.
        let bytes = sth_signing_bytes(r.sth.tree_size, &r.sth.root);
        if !verifier.verify(&bytes, &r.sth.signature) {
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
        let qp = MockQuoteProvider::generate();
        let qv = qp.verifier();
        let mut anchor = LocalAnchor::default();

        let honest = m("honest");
        let idx = log.append(&honest);
        let sth = log.signed_tree_head(&signer);
        anchor.anchor(&sth);

        let nonce = Nonce(sha256(&[b"n1"]));
        let client = super::kem::ClientKeypair::generate();
        let kem = client.public_key();
        let (ct, _) = super::kem::encapsulate(&kem.0).unwrap();

        let good = Receipt {
            quote: qp.quote(&nonce, &kem, &honest),
            nonce: nonce.clone(),
            kem_pubkey: kem.clone(),
            kem_ciphertext: ct.clone(),
            inclusion: log.inclusion_proof(idx).unwrap(),
            sth: log.signed_tree_head(&signer),
        };
        assert!(verify::verify_receipt(&good, &nonce, &qv, &signer, &anchor).is_ok());

        // Ghost build, never logged: forge a receipt reusing the honest inclusion proof.
        let ghost = m("ghost");
        let forged = Receipt {
            quote: qp.quote(&nonce, &kem, &ghost),
            nonce: nonce.clone(),
            kem_pubkey: kem.clone(),
            kem_ciphertext: ct.clone(),
            inclusion: log.inclusion_proof(idx).unwrap(),
            sth: log.signed_tree_head(&signer),
        };
        assert_eq!(
            verify::verify_receipt(&forged, &nonce, &qv, &signer, &anchor),
            Err(verify::VerifyError::InclusionInvalid)
        );
    }

    #[test]
    fn slh_dsa_sign_verify_roundtrip() {
        use super::slh::{SlhSigner, SIG_LEN};
        let signer = SlhSigner::generate().unwrap();
        let verifier = signer.verifier();
        let msg = sth_signing_bytes(7, &sha256(&[b"root"]));
        let sig = signer.sign(&msg);
        assert_eq!(sig.len(), SIG_LEN);
        assert!(verifier.verify(&msg, &sig));
        assert!(!verifier.verify(&sha256(&[b"other"]), &sig));
        // a public key recovered from bytes verifies identically (client-side path)
        let v2 = super::slh::SlhVerifier::from_bytes(&signer.public_key_bytes()).unwrap();
        assert!(v2.verify(&msg, &sig));
    }

    #[test]
    fn full_receipt_with_real_slh_dsa() {
        use super::slh::SlhSigner;
        let mut log = TransparencyLog::new();
        let signer = SlhSigner::generate().unwrap();
        let verifier = signer.verifier(); // client holds only this
        let qp = MockQuoteProvider::generate();
        let qv = qp.verifier();
        let mut anchor = LocalAnchor::default();

        let honest = m("honest");
        let idx = log.append(&honest);
        anchor.anchor(&log.signed_tree_head(&signer));

        let nonce = Nonce(sha256(&[b"n"]));
        let client = super::kem::ClientKeypair::generate();
        let kem = client.public_key();
        let (ct, _) = super::kem::encapsulate(&kem.0).unwrap();
        let r = Receipt {
            quote: qp.quote(&nonce, &kem, &honest),
            nonce: nonce.clone(),
            kem_pubkey: kem.clone(),
            kem_ciphertext: ct,
            inclusion: log.inclusion_proof(idx).unwrap(),
            sth: log.signed_tree_head(&signer),
        };
        assert!(verify::verify_receipt(&r, &nonce, &qv, &verifier, &anchor).is_ok());
    }

    #[test]
    fn binding_is_tautological_without_a_trusted_quote() {
        // The point of the QuoteVerifier: the binding check ALONE cannot catch a lying
        // provider; only a hardware-root signature can. This test proves both halves.
        let mut log = TransparencyLog::new();
        let signer = super::slh::SlhSigner::generate().unwrap();
        let mut anchor = LocalAnchor::default();

        // The client pins the HONEST hardware root's public key out of band.
        let honest_root = MockQuoteProvider::generate();
        let qv = honest_root.verifier();

        let nonce = Nonce(sha256(&[b"n"]));
        let client = super::kem::ClientKeypair::generate();
        let kem = client.public_key();
        let (ct, _) = super::kem::encapsulate(&kem.0).unwrap();

        // The attacker controls the keyserver and even LOGS a ghost build, so inclusion is
        // valid — the ONLY thing left to stop acceptance is the quote signature.
        let ghost = m("backdoored");
        let gidx = log.append(&ghost);
        let sth = log.signed_tree_head(&signer);
        anchor.anchor(&sth);

        // (a) The binding is self-consistent for ANY measurement — this is the tautology.
        let bound = honest_root.quote(&nonce, &kem, &ghost);
        assert_eq!(bound.report_data, compute_report_data(&nonce, &kem, &ghost));

        // (b) The real attacker has a DIFFERENT hardware key; its validly-bound quote is NOT
        //     signed by the trusted root → rejected at step 0, before inclusion even matters.
        let attacker_root = MockQuoteProvider::generate();
        let forged = Receipt {
            quote: attacker_root.quote(&nonce, &kem, &ghost),
            nonce: nonce.clone(),
            kem_pubkey: kem.clone(),
            kem_ciphertext: ct.clone(),
            inclusion: log.inclusion_proof(gidx).unwrap(),
            sth: sth.clone(),
        };
        assert_eq!(
            verify::verify_receipt(&forged, &nonce, &qv, &signer.verifier(), &anchor),
            Err(verify::VerifyError::QuoteSignatureInvalid)
        );

        // (c) With the honest root's quote the SAME receipt verifies — so the hardware-root
        //     signature is exactly what stands between "logged ghost" and "accepted". (In the
        //     mock the honest root will sign anything; a real TPM only signs the loaded build.)
        let accepted = Receipt {
            quote: honest_root.quote(&nonce, &kem, &ghost),
            ..forged.clone()
        };
        assert!(verify::verify_receipt(&accepted, &nonce, &qv, &signer.verifier(), &anchor).is_ok());
    }

    #[test]
    fn consistency_proofs_validate_for_all_sizes() {
        use super::log::{verify_consistency, TransparencyLog};
        for n in 1u64..=33 {
            let mut log = TransparencyLog::new();
            let mut roots = vec![[0u8; 32]; (n + 1) as usize]; // roots[size] = root at that size
            for i in 0..n {
                log.append(&m(&format!("c-{i}")));
                roots[(i + 1) as usize] = log.root();
            }
            let root_n = roots[n as usize];
            for first in 1..n {
                let proof = log.consistency_proof(first).unwrap();
                let root_first = roots[first as usize];
                assert!(
                    verify_consistency(&proof, &root_first, &root_n),
                    "consistency n={n} first={first} should verify"
                );
                // tampered second root must be rejected
                assert!(!verify_consistency(&proof, &root_first, &m("evil").0));
                // tampered first root must be rejected
                assert!(!verify_consistency(&proof, &m("evil").0, &root_n));
            }
            // first == n: empty proof, tree consistent with itself
            let p = log.consistency_proof(n).unwrap();
            assert!(verify_consistency(&p, &root_n, &root_n));
        }
    }

    #[test]
    fn rewritten_history_fails_consistency() {
        use super::log::{verify_consistency, TransparencyLog};
        let mut log = TransparencyLog::new();
        log.append(&m("a"));
        let root1 = log.root();
        log.append(&m("b"));
        log.append(&m("c"));
        let root3 = log.root();

        let proof = log.consistency_proof(1).unwrap();
        assert!(verify_consistency(&proof, &root1, &root3));

        // A fork that secretly rewrote leaf 0 has a different size-1 root; the honest
        // proof cannot reconcile it with the size-3 root.
        let mut fork = TransparencyLog::new();
        fork.append(&m("a-rewritten"));
        assert!(!verify_consistency(&proof, &fork.root(), &root3));
    }

    #[test]
    fn xwing_kem_channel_agrees() {
        use super::kem::{derive_session_key, encapsulate, ClientKeypair, CIPHERTEXT_LEN};
        let client = ClientKeypair::generate();
        let pk = client.public_key();

        let (ct, server_ss) = encapsulate(&pk.0).expect("valid pubkey");
        assert_eq!(ct.len(), CIPHERTEXT_LEN);
        let client_ss = client.decapsulate(&ct).expect("valid ciphertext");
        assert_eq!(server_ss, client_ss, "shared secret must agree");

        let nonce = Nonce(sha256(&[b"n"]));
        let meas = m("loader");
        let k_server = derive_session_key(&server_ss, &nonce, &ct, &meas);
        let k_client = derive_session_key(&client_ss, &nonce, &ct, &meas);
        assert_eq!(k_server, k_client, "derived session keys must match");

        // A tampered ciphertext yields a different secret (ML-KEM implicit rejection),
        // so the derived session key diverges — the channel fails closed.
        let mut bad = ct.clone();
        bad[0] ^= 0x01;
        let bad_ss = client.decapsulate(&bad).expect("still parses");
        assert_ne!(bad_ss, client_ss, "tampered ciphertext must not agree");

        // A malformed (wrong-length) public key is rejected.
        assert!(encapsulate(b"too-short").is_none());
    }

    #[test]
    fn witness_cosign_meets_threshold() {
        use super::log::TransparencyLog;
        use super::slh::SlhSigner;
        use super::witness::{Witness, WitnessAnchor};
        use super::CosignedSth;

        let mut witnesses: Vec<Witness> = (0..3).map(Witness::generate).collect();
        let signer = SlhSigner::generate().unwrap();
        let mut log = TransparencyLog::new();
        log.append(&m("a"));
        let sth = log.signed_tree_head(&signer);

        let cosignatures: Vec<_> = witnesses
            .iter_mut()
            .map(|w| w.cosign(&sth, None).unwrap())
            .collect();
        let cosigned = CosignedSth {
            sth: sth.clone(),
            cosignatures,
        };

        // Quorum of 2 reached by 3 cosignatures.
        let trusted: Vec<_> = witnesses.iter().map(|w| (w.id(), w.verifier())).collect();
        let mut anchor = WitnessAnchor::new(trusted, 2);
        assert!(anchor.ingest(&cosigned, None));
        assert!(anchor.is_anchored(&sth));

        // A single cosignature does not meet threshold 2.
        let trusted2: Vec<_> = witnesses.iter().map(|w| (w.id(), w.verifier())).collect();
        let mut anchor2 = WitnessAnchor::new(trusted2, 2);
        let one = CosignedSth {
            sth: sth.clone(),
            cosignatures: vec![cosigned.cosignatures[0].clone()],
        };
        assert!(!anchor2.ingest(&one, None));
        assert!(!anchor2.is_anchored(&sth));
    }

    #[test]
    fn witness_refuses_to_cosign_a_fork() {
        use super::log::TransparencyLog;
        use super::slh::SlhSigner;
        use super::witness::Witness;

        let signer = SlhSigner::generate().unwrap();
        let mut w = Witness::generate(0);

        // The witness attests the honest size-1 tree.
        let mut log = TransparencyLog::new();
        log.append(&m("a"));
        let sth1 = log.signed_tree_head(&signer);
        let root1 = sth1.root;
        assert!(w.cosign(&sth1, None).is_some());

        // The honest log grows; with a valid consistency proof the witness cosigns again.
        log.append(&m("b"));
        let sth2 = log.signed_tree_head(&signer);
        let good = log.consistency_proof(1).unwrap();
        assert!(w.cosign(&sth2, Some(&good)).is_some());

        // A fork that rewrote leaf 0: its consistency proof is for a different size-1
        // root than the one the witness saw, so reconciliation fails → refuse.
        let mut fork = TransparencyLog::new();
        fork.append(&m("a-rewritten"));
        fork.append(&m("b"));
        fork.append(&m("c"));
        let forked = fork.signed_tree_head(&signer);
        // (witness last = size 2; ask it to jump to the forked size-3 head)
        let forks_proof = fork.consistency_proof(2).unwrap();
        assert!(w.cosign(&forked, Some(&forks_proof)).is_none());
        assert!(w.cosign(&forked, None).is_none());
        // sanity: root1 really differs from the fork's history
        assert_ne!(root1, fork.root());
    }

    #[test]
    fn witness_anchor_rejects_same_size_equivocation() {
        // Client-side defence-in-depth: even if a COLLUDING witness quorum cosigns two different
        // roots at the same size (bypassing the witness-side fork refusal), the client catches it.
        use super::log::TransparencyLog;
        use super::slh::SlhSigner;
        use super::witness::WitnessAnchor;
        use super::{cosignature_bytes, CosignedSth, WitnessCosignature};

        let op = SlhSigner::generate().unwrap();
        let mut log_a = TransparencyLog::new();
        log_a.append(&m("a"));
        let sth_a = log_a.signed_tree_head(&op);
        let mut log_b = TransparencyLog::new();
        log_b.append(&m("b"));
        let sth_b = log_b.signed_tree_head(&op);
        assert_ne!(sth_a.root, sth_b.root);

        let mal = SlhSigner::generate().unwrap();
        let mut anchor = WitnessAnchor::new(vec![(0u32, mal.verifier())], 1);
        let cosig = |sth: &SignedTreeHead| CosignedSth {
            sth: sth.clone(),
            cosignatures: vec![WitnessCosignature {
                witness_id: 0,
                signature: mal.sign(&cosignature_bytes(sth.tree_size, &sth.root)),
            }],
        };
        assert!(anchor.ingest(&cosig(&sth_a), None)); // trust (1, root_a)
        assert!(!anchor.ingest(&cosig(&sth_b), None)); // same size, different root → rejected
        assert!(anchor.is_anchored(&sth_a) && !anchor.is_anchored(&sth_b));
    }
}
