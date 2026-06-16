# EXTRACTION.md — dossiers Protocol-01 + sélection de crates

> Synthèse des 5 agents de reconnaissance (2026-06-16) sur `D:\Protocol-01` (READ-ONLY ;
> ignorer `.claude\worktrees\`). Persisté ici parce que coûteux à régénérer. Alimente M1–M5.

## 1. Merkle / log append-only

- `programs/p01_stark_verifier/src/merkle.rs` — **SHA-256**, `verify_merkle_path` (L22-46) et
  `hash_pair`/`merkle_root_from_hashes` (L51-83) **std-portables, couplage quasi nul** → lift direct (~30 min).
- **PAS de séparation leaf/node** chez p01 (faille second-preimage) → on ajoute `0x00/0x01` (déjà fait en M0).
- **Aucune preuve de consistance** (RFC6962) nulle part dans le repo → **à construire** (~6-8 h).
- Génération de preuve d'inclusion : seulement en TS (`packages/privacy-toolkit/src/merkle/proofFromSubtrees.ts`
  L27-59, `incrementalTree.ts` L10-16) → à porter pour l'arbre incrémental `filled_subtrees` (~3-4 h).
- `zk_shielded/src/state/merkle_tree.rs` & `_v3.rs` : Poseidon, **lourdement couplés Anchor** (structs jetables,
  logique salvageable). `MerkleProof::verify` = stub bidon, ne PAS réutiliser.
- **M1 effort total estimé : ~10-13 h.** (M0 a déjà un Merkle RFC6962 correct, non incrémental.)

## 2. Signatures hash-based

- WOTS+ `programs/p01_quantum_vault/src/state/winternitz_vault.rs` : `w=16`, **67 chaînes** (64+3), SHA-256,
  sig/pk 2144 o. **Seulement le VERIFY on-chain existe** (chain-walk `lib.rs:219-234`). **Aucun signer/keygen** → à écrire.
- SPHINCS+ `programs/p01_quantum_wallet/src/state/sphincs_sig_buffer.rs` : déclare `Sha2_128f`, mais **verify stubbé**
  (`recover.rs:245-265` → `SphincsVerifierNotWired`). Lib visée `slh-dsa` jamais câblée (conflit `signature`/ed25519 en contexte Solana ; **non bloquant off-chain**). **Reference-only.**
- **Décision STH = SLH-DSA** (stateless). XMSS-over-WOTS+ = 2-4 j (signer à écrire, STATEFUL = footgun de réutilisation
  d'index → forge). Différé en optimisation post-MVP, WOTS+ p01 = oracle de test seulement.

## 3. Ancrage on-chain (`ChainAnchor`, optionnel post-MVP)

- **Ne PAS réutiliser** le STARK verifier (`p01_stark_verifier` prouve des circuits ZK, hors-sujet).
- Cloner ~80 lignes : un compte Anchor `SthAnchor { log_authority, epoch, root:[u8;32], timestamp, bump }`,
  PDA `["sth", log_id, epoch]`, instruction `anchor_root(epoch, root)` monotone. Templates : `ProofBuffer`,
  `zk_shielded::MerkleTreeState`, `p01_registry`.
- Vérif client = **simple lecture chaîne** (`getAccountInfo` + compare root) — **le verifier p01 n'est pas nécessaire**.
- **Effort : 3-5 j localnet.** Risques : gestion clé/rent/liveness du signataire d'ancrage ; scope-creep du modèle
  de confiance (finalité, reorg, monitoring). Garder un write+read mince.

## 4. Binding hybride + HKDF (référence TS → Rust, M2)

Source canonique : `packages/specter-sdk/src/utils/crypto.ts:139-160`.
```
ikm        = X25519_secret(32) ‖ ML-KEM-768_secret(32)     # classique D'ABORD
transcript = SHA256( eph_pub ‖ kem_ct )
info       = b"<label>" ‖ transcript
session_key= HKDF-SHA256(salt=∅, ikm, info, L=32)
report_data= SHA256( DOMAIN ‖ nonce ‖ kem_pubkey ‖ measurement )   # DOMAIN ajouté (p01 l'omet)
```
Gardes : figer l'ordre 32+32 (frontière non-ambiguë) ; le chemin relay (`relay/encrypt.ts:48-54`) OMET le transcript
binding → utiliser la version stealth (bindée). Ne pas porter `deriveKeyFromPassword` (KDF maison).

## 5. Sélection de crates PQ (mi-2026) — pour M1/M2

| Job | Crate retenue | Notes |
|---|---|---|
| **STH signing (SLH-DSA, FIPS 205)** | `fips205 = "0.4.0"` | `no_std`, heap-free, **WASM-ready**, verify sans RNG. Param **SLH-DSA-SHA2-128s** (sig 7856 o). Alt : `slh-dsa = "0.2.0-rc.5"` (RustCrypto, RC). |
| **Binding hybride** | `x-wing = "0.1.0-rc.0"` | X25519+ML-KEM-768, combiner unique (draft-connolly-xwing-06). Tire `ml-kem = "0.3.2"` + `x25519-dalek = "3.0.0-pre.6"`. |
| **Variante vérifiée** | `libcrux-kem = "0.0.8"` | Expose `XWingKemDraft06` **et** `X25519MlKem768Draft00` (TLS). Cœur ML-KEM **formellement vérifié** (F*/hax). WASM non documenté → valider. |

**Tailles pour le bench** : ML-KEM-768 ct **1088**, pk 1184 ; X25519 32 ; SLH-DSA-128s sig **7856**, 128f **17088** ;
X-Wing pk 1216 / ct 1120 ; (ECC ref : sig/clé ~32-64).
**WASM** : `getrandom` v0.3 → backend `wasm_js` requis pour la *keygen* ; le **vérifieur ne fait que verify → pas de RNG**,
donc `fips205`/`ml-kem` verify compilent proprement en `wasm32`.
**Garde-fou** : **aucune de ces crates n'est auditée indépendamment** (mi-2026) ; seul le cœur ML-KEM de libcrux est
formellement vérifié. Étiqueter « maintained, vector-tested, unaudited » dans le README ; prod = revue propre.
