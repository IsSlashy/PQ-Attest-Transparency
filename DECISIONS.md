# DECISIONS.md — journal de décisions (ADR)

> Décisions bloquantes tranchées avant Phase 1. Discipline BRIEF : « rien d'autre tant que ces deux points ne sont pas écrits ». Date : 2026-06-16.

---

## ADR-001 — Licence : **MIT**

- **Contexte** : le code est extrait / porté depuis Protocol-01, qui est *ALL RIGHTS RESERVED*. Ce repo est standalone et destiné à être public et reproductible (garde-fou BRIEF §6 : « tout doit être reproductible »).
- **Décision** : **MIT**. Permissif, simple, sans ambiguïté ; signal « rien à cacher » cohérent avec la philosophie reproductibilité.
- **Conséquences** :
  - Tout code porté de Protocol-01 vers ce repo est re-licencié MIT par son détenteur (même auteur — pas de tiers à consulter).
  - Le reste de Protocol-01 demeure privé / ARR ; seul le code effectivement copié ici tombe sous MIT.
  - Aucune dépendance copy-left n'entrera dans l'arbre (vérifier les crates : `ml-kem`, `libcrux-*` sont Apache-2.0/MIT — compatibles).
- **TODO avant publication** : remplacer le détenteur `Slashy` dans `LICENSE` par le nom légal / handle définitif.

---

## ADR-002 — Langage du MVP : **Rust**

- **Décision** : Rust pour le cœur (fidèle BRIEF §5 ; crédibilité « bas niveau » pour le public sécu). Python autorisé pour bench/harness annexe uniquement.
- **Conséquence honnête — correction du RESEARCH §4.** Le « ~70 % extraction » était calculé sur des assets **TypeScript** (`@noble/post-quantum`, Merkle de `privacy-toolkit`). En Rust, la réalité est différente et il faut le dire :

| Besoin de l'artefact | Asset Protocol-01 (Rust réel) | Statut honnête |
|---|---|---|
| **Signature hash-based du STH** (cœur PQ) | WOTS+ — `programs/p01_quantum_vault/src/state/winternitz_vault.rs` (w=16, 67 chaînes, SHA-256, 256-bit classique / 128-bit quantique). SPHINCS+/SLH-DSA — `programs/p01_quantum_wallet/src/state/sphincs_sig_buffer.rs`. | **Port Anchor→std Rust**, pas copier-coller. WOTS+ est *one-time* → bâtir la couche *many-time* (XMSS sur WOTS+) **ou** utiliser SLH-DSA (stateless). Primitif + paramètres présents ; le signer std reste à porter. |
| **Log append-only (Merkle)** | `programs/p01_stark_verifier/src/merkle.rs` ; arbres incrémentaux `programs/zk_shielded/src/state/merkle_tree.rs`, `merkle_tree_v3.rs` | **Port as-reference**. Structure append-only adaptée, à sortir du contexte Anchor/BPF. |
| **Binding clé HNDL-safe (ML-KEM)** | — (aucun Rust ; TS `@noble` seulement) | **Crate externe** : `ml-kem` (RustCrypto) ou `libcrux-ml-kem` (formellement vérifié). Pas de l'extraction. |
| **Option preuve d'inclusion en STARK** | `stark/`, `programs/p01_stark_verifier/`, `services/prover/` | Extractible Rust, mais **hors MVP** (option §5). |
| Mock TPM/quote, keyserver, loader, reçu client, CLI | — | **Neuf.** |

- **Estimation corrigée** : ~**35–45 %** extraction-as-reference (vs 70 % annoncé pour TS). La brique la plus dure et la plus différenciante — la **signature hash-based PQ** — est celle où l'antécédent est réel. Argument plus solide que « 70 % copier-coller ».

---

## ADR-003 — Signature du STH : **SLH-DSA pour le MVP** (XMSS en note prod) — *à confirmer début Phase 1*

- SLH-DSA (SPHINCS+, FIPS 205) : **stateless**, pas de footgun d'état ; signatures grosses (~7–30 KB selon paramètres). Antécédent : `sphincs_sig_buffer.rs`.
- XMSS / LMS (RFC 8391 / 8554) : **stateful** (réutiliser un index de feuille = forge possible → catastrophe), signatures plus petites, recommandé NSA pour firmware/supply-chain. Antécédent : WOTS+ vault (la feuille OTS).
- **Reco** : SLH-DSA pour le MVP — la statefulness de XMSS est un piège pour une démo *et* pour une vraie log append-only multi-signataire. Documenter XMSS/LMS comme « ce que la prod ferait pour réduire la taille ».
- **✅ RÉSOLU (2026-06-16, agents recon)** : **SLH-DSA via `fips205 = "0.4.0"`, param SHA2-128s.** Confirmé : aucun signer WOTS+ n'existe dans p01 (verify-only), XMSS = 2-4 j à écrire ; SLH-DSA crate = heures, `no_std`/WASM-ready. Détails dans `docs/EXTRACTION.md`.

---

## ADR-004 — Anti-équivocation : abstraction `Anchor` (Web2-core, chaîne optionnelle)

- **Problème** : empêcher le *split-view* (le log montre deux historiques différents à deux clients). En Web2 ça coûte soit un réseau de *gossip* à amorcer, soit une fédération de *témoins* indépendants à recruter/faire confiance. Une chaîne publique fournit un médium append-only déjà amorcé sur lequel on n'ancre que la **racine** (32 o) par époque — O(1).
- **Décision** : le cœur du log ne sait pas *comment* sa racine devient non-équivoquable. Interface `trait Anchor` avec implémentations interchangeables :
  - `LocalAnchor` (démo) ;
  - `WitnessAnchor` (**Web2, cœur MVP**) : STH co-signés par des témoins indépendants — *architecturalement adoptable en Web2, sans aucune blockchain* (réf., pas drop-in : présuppose un quote matériel réel, des crates auditées, une fédération de témoins opérée, et des builds reproductibles) ;
  - `ChainAnchor` (**option post-MVP**) : racine ancrée on-chain via le verifier Protocol-01.
- **Cadre d'honnêteté** : la chaîne n'apporte **pas de la vitesse** (elle est plus lente). Ce qu'elle supprime, c'est le **coût de bootstrap/opération d'une fédération de témoins**. À écrire tel quel dans le README ; ne jamais vendre « blockchain = performance ».
- **Conséquence** : le MVP est complet et défendable en Web2 pur. La chaîne est anticipée par l'interface mais hors du chemin critique < 5 min.

---

## ADR-005 — Primitives PQ = crates auditées (pas de crypto maison) ; rôle réel de Protocol-01

- **Décision** : ML-KEM et SLH-DSA viennent de **crates auditées/maintenues** (recon agent en cours : RustCrypto `ml-kem`/`slh-dsa`, `libcrux`, `x25519-dalek` pour l'hybride). On ne porte PAS de SLH-DSA maison — ce serait une faute de crédibilité.
- **Conséquence honnête sur l'edge** : si les primitives sont des crates, l'extraction Protocol-01 se concentre sur (a) le **Merkle** (port), (b) l'**ancrage on-chain** (option), (c) la **fluence hash-based** (raisonner XMSS vs SLH-DSA, offrir la variante petite-signature). Donc **Protocol-01 n'est pas « 70 % du code »** : c'est ce qui te permet d'atteindre les *variantes fortes* (ancrage chaîne, inclusion STARK, XMSS petite-sig) qu'un solo lambda ne peut pas atteindre. Meilleur moat que « copier-coller », et honnête.
- **Valeur de l'artefact** = l'**intégration** (format de reçu + vérifieur client CLI/WASM + threat model), pas une crypto inédite. Cohérent BRIEF « l'actif c'est l'exécution ».

---

## ADR-006 — Ce que l'artefact prouve réellement : non-équivocation, pas « détection de backdoor »

- **Précision décisive** : un *measurement* est le hash d'un build **opaque** (la source du loader d'Anthropic n'est pas publique). Voir « build M est dans le log » ne dit donc PAS que M est honnête.
- **Ce que la transparence achète vraiment** : (a) **non-équivocation** — un seul historique public, impossible de montrer M_propre à l'un et M_piégé à l'autre ; (b) **responsabilité tamper-evident** — si un backdoor est un jour découvert, le log prouve de façon non-répudiable qu'il a été servi à tous, à cette date. Exactement la valeur de Certificate Transparency.
- **Dépendance à nommer** : la force « mordante » réelle exige des **builds reproductibles** (provenance type SLSA/in-toto). **Hors-scope MVP** — on la *documente* comme « ce qui rend la transparence mordante », on ne la construit pas.
- **Règle de pitch** : ne jamais écrire « tu sauras si c'est piégé ». Écrire « ils ne peuvent plus mentir en secret ni réécrire l'histoire ».

---

## Roadmap (séquencée pour dé-risquer l'intégration d'abord)

- **M0 — squelette qui marche, crypto PLACEHOLDER** (SHA-256 stand-ins). Les deux chemins ✅/❌ de bout en bout. *✅ FAIT — `cargo build` + 3 tests verts (inclusion 1..33, round-trip, attaque) + démo CLI.*
- **M1 — log réel** : Merkle append-only (port p01) + STH signé **SLH-DSA** (crate) + preuves d'inclusion & de consistance.
- **M2 — binding HNDL-safe** : KEM hybride **X25519 + ML-KEM-768** lié dans `report_data` via `QuoteProvider` mock. *✅ FAIT — X-Wing (`x-wing` crate), ct 1120 o ; canal de session HKDF transcript-bound vérifié des deux côtés ; 8 tests verts.*
- **M3 — vérifieur client** : crate `verify` compilé en **CLI + WASM** (le livrable central). *✅ FAIT — `pqtl-wasm` (wasm-bindgen), build wasm-pack web+node, vérifieur RNG-free (feature-gating `rng` + serde) ; prouvé en navigateur et en Node : honnête=accept, falsifié=`SthSignatureInvalid`, split-view=`NotAnchored`.*
- **M4 — anti-split-view Web2** : `WitnessAnchor` (co-signature de STH). MVP complet ici, zéro blockchain. *✅ FAIT — module `witness` : `Witness` (cosign + refus de fork via consistance), `WitnessAnchor` (quorum, RNG-free → wasm-ok) ; 2 tests + scénario 4 de la démo.*
- **M5 — bench + honnêteté** : tailles (SLH-DSA vs ECC, ct ML-KEM, preuve d'inclusion), latence vérif, README threat-model (prouvé / supposé / mocké).
- **(Optionnel) `ChainAnchor`** : ancrage on-chain via verifier p01. Hors critère < 5 min.

Chaque frontière de confiance = un trait avec un mock + un chemin réel documenté : `QuoteProvider` (mock TDX → vrai TDX), `Anchor` (témoins Web2 → chaîne).

---

## MVP figé — contrat de la Phase 1

Reprend RESEARCH §5, **figé** (plus de scope creep sans nouvel ADR) :

1. **CLI Rust.** Deux chemins démontrés :
   - ✅ build **loggé + attesté** → keyserver libère la clé (ML-KEM) → client vérifie inclusion + STH → **accepté**.
   - ❌ build **fantôme non loggé** (attaque ciblée / split-view simulée) → pas de preuve d'inclusion → **client refuse**.
2. **Composants** : mock TPM/TDX quote ; transparency log (Merkle append-only + STH signé SLH-DSA) ; keyserver (release **ssi** attesté **ET** inclus dans le log) ; binding `report_data = H(nonce ‖ ML-KEM pubkey ‖ measurement)` avec KEM hybride **X25519 + ML-KEM-768** ; reçu client vérifié **côté client, en PQ**.
3. **Bench** : tailles (sig PQ vs ECC ; ct ML-KEM ; preuve d'inclusion), latence de vérification client.
4. **Critère de réussite** : un dev sécu lance la démo en **< 5 min** et voit le client **refuser un loader que l'attestation classique seule aurait accepté**.
5. **Hors scope explicite** : racine TPM (reste classique, hardware) ; vrai hardware CC ; réseau d'auditeurs réel (gossip anti-split-view seulement esquissé) ; preuve d'inclusion STARK (option, pas MVP).

---

## État

- [x] ADR-001 Licence (MIT) — écrit, `LICENSE` créé.
- [x] ADR-002 Langage (Rust) — écrit, extraction corrigée.
- [x] ADR-003 SLH-DSA vs XMSS — **résolu : SLH-DSA via `fips205`** (agents recon).
- [x] ADR-004 Anchor (Web2-core / chain-optionnel) — écrit.
- [x] ADR-005 Primitives = crates auditées — écrit, crates choisies (`docs/EXTRACTION.md`).
- [x] ADR-006 Valeur = non-équivocation — écrit, reflété README + RESEARCH §6.
- [x] MVP figé — contrat ci-dessus.
- [x] **M0 — squelette livré** (build + tests + démo).
- [~] M1 — **STH SLH-DSA + inclusion + consistance RFC6962 faits** (7 tests verts ; bench sig 7856 o / pk 32 o ; consistance validée tailles 1..33 + test de réécriture d'historique). Reste : Merkle incrémental (optim O(log n), différable).

→ **M0–M4 verts** (10 tests + smoke WASM). **MVP complet et défendable EN WEB2 PUR** : SLH-DSA + RFC6962 inclusion/consistance + X-Wing (HNDL) + co-signature de témoins (anti-split-view), vérifieur compilé en WASM. Reste : **M5 — bench + README threat-model**, puis `ChainAnchor` on-chain (optionnel).
