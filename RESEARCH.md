# RESEARCH.md — PQ-Attest-Transparency (Phase 0)

> Livrable Phase 0. Recherche AVANT de coder. Réponses sourcées + schéma du flow annoté « ici classique → ici PQ → ici transparence ».
>
> Statut : **recherche, rien n'est codé.** Date : 2026-06-16. R&D solo.
> Discipline (héritée du BRIEF) : l'actif c'est l'exécution ; standalone ; honnête sur les limites ; pas de framing « notice me ».

---

## 0. TL;DR

L'angle initial du BRIEF (« PQ-hardening du key-release ») a été rattrapé en 12 mois : TPM PQ en hardware (Infineon, SealSQ), inférence chiffrée PQ déployée (Chutes), preuve ZK d'inférence (zkAgent, DeepProve). Construire ça aujourd'hui = arriver deuxième.

**Le trou réel n'est pas la crypto, c'est *qui vérifie*.** Dans l'inférence confidentielle d'Anthropic, c'est le keyserver d'Anthropic qui vérifie Anthropic ; l'utilisateur ne vérifie rien et ne peut pas détecter une attaque **ciblée** (un loader backdooré servi à une seule personne, signé par la CI légitime). C'est le problème exact que **Certificate Transparency** (RFC 6962) a résolu pour les CA TLS — mais personne ne l'a fait pour l'inférence confidentielle, **et personne ne l'a fait post-quantique + vérifiable côté utilisateur + lié à la session live**.

**Artefact cible :** *Certificate Transparency pour l'inférence confidentielle, quantum-safe et vérifiable par l'utilisateur.* Log de transparence append-only post-quantique (Merkle + signature hash-based) des builds de loader attestés ; le key-release exige une **preuve d'inclusion** dans le log ; le client reçoit un **reçu de session** et vérifie tout côté client, en PQ, en < 5 min.

---

## 1. L'angle, reformulé (vs BRIEF v1)

Le BRIEF v1 liait deux primitives à deux menaces qu'il faut séparer :

| Primitive PQ | Menace couverte | Urgence |
|---|---|---|
| **KEM PQ (ML-KEM)** sur le canal de clés | **HNDL** : ciphertext capturé aujourd'hui, cassé plus tard. Protège **rétroactivement** les données d'aujourd'hui. | Haute, maintenant. |
| **Signatures PQ (ML-DSA/SLH-DSA)** sur l'attestation/le log | Forge par un adversaire quantique **actif** (pas rétroactif). Menace les déploiements **futurs** post-CRQC. | Moyenne. |
| **Transparence (Merkle + STH signé)** | Attaque **ciblée / split-view** par un provider compromis ou contraint. **Orthogonale au quantique** mais non couverte par l'attestation seule. | **Le vrai trou.** |

La nouveauté de l'artefact est dans la **3ᵉ ligne combinée aux deux premières** : une transparence *post-quantique* et *liée à la session*, pas juste un log de supply-chain classique.

---

## 2. Phase 0 — Réponses sourcées

### Q1 — État de l'art : attestation distante, son modèle, et la transparence

**Le modèle de référence est RATS (RFC 9334).** Trois rôles : l'**Attester** produit des *Evidence* (claims : mesures, config, télémétrie) ; le **Verifier** les confronte à des *Reference Values* + *Endorsements* via une *Appraisal Policy* et produit des *Attestation Results* ; la **Relying Party** décide en fonction de ces résultats. (RFC 9334, IETF, 2023.)

> Mapping sur Anthropic : le **loader** = Attester ; le **keyserver** = Verifier **et** Relying Party à la fois. C'est précisément le point faible : Verifier et Relying Party sont la même entité (Anthropic). L'utilisateur final n'est *aucun* des trois rôles → il ne vérifie rien.

**La transparence comme couche par-dessus l'attestation existe — mais classique et conceptuelle.** Un cadre académique « Confidential Computing Transparency » (arXiv 2409.03720) propose d'exposer les composants attestables d'un système CC à des certifieurs, « à la manière de Certificate Transparency ». Les « attestable builds » (arXiv 2505.02521) enregistrent l'attestation d'un build TEE dans un log de transparence pour qu'un destinataire vérifie qu'un artefact provient bien d'un snapshot de source donné. **Ce sont des position papers / outils de build, classiques, non liés à une session d'inférence live, et non vérifiés côté utilisateur final.**

**Certificate Transparency (RFC 6962)** donne la mécanique exacte à transposer : Merkle tree append-only, *Signed Tree Heads* (STH), **preuves d'inclusion** et **preuves de consistance** entre deux STH (prouve l'append-only sans relire l'arbre). Le **split-view** (le log sert deux versions de lui-même à des clients différents) est le risque résiduel, contré par le **gossip** de STH entre clients.

**Conclusion Q1 :** la brique conceptuelle (transparence pour CC) et la mécanique (CT) existent séparément. **Aucune mise en œuvre qui tourne, post-quantique, liée à la session d'inférence, et vérifiée côté user.**

### Q2 — Les TPM supportent-ils le PQ ? Où se place la couche PQ ?

**Pas encore en pratique sur le parc déployé, ça arrive en hardware fin 2026.** Infineon annonce des OPTIGA TPM avec ML-KEM/ML-DSA embarqués (root of trust quantum-resilient pour « Physical AI » / Jetson Thor). SealSQ QVault TPM vise FIPS 203/204, Common Criteria EAL5+, **sampling/dispo prévus novembre 2026**. Côté recherche : attestation distante PQ « stateless » pour IoT via TPM+DICE (IEEE 2026), attestation PQ anonyme via **XMSS/LMS** (brevets/2026).

**Implication de placement :** le *quote* TPM d'un parc déployé aujourd'hui est signé en RSA/ECC, **fixé en hardware** — on ne peut pas le rendre ML-DSA après coup. Donc la couche PQ et la couche transparence se placent **au-dessus du TPM**, dans :
1. le **binding** de la clé de session (ML-KEM, HNDL-safe) ;
2. la **signature du log** (hash-based, indépendante du TPM) ;
3. la **preuve d'inclusion** vérifiée par le client.

> Posture honnête à documenter dans le README : tant que le quote racine reste classique, un adversaire quantique *actif* peut forger l'attestation de bas niveau. Notre couche protège (a) la confidentialité HNDL **maintenant** et (b) la détectabilité des attaques ciblées **maintenant**, et devient pleinement PQ quand le parc passe aux TPM PQ. On ne prétend pas durcir la racine hardware.

### Q3 — Hybride classique + PQ : pourquoi et comment

**Consensus IETF/NIST = hybride, pour ne jamais être *pire* que le classique** si le schéma PQ casse. Pour le KEM, le défaut de fait est **X25519 + ML-KEM-768** : adopté par le TLS WG en mars 2025 (`draft-ietf-tls-ecdhe-mlkem`, groupe `X25519MLKEM768`) et déjà déployé dans TLS 1.3, QUIC, SSH, Signal. La construction générique propre est **X-Wing** (`draft-connolly-cfrg-xwing-kem`, X25519 + ML-KEM-768), réutilisable hors TLS. NIST note dans SP 800-227 (en cours) qu'il manque encore une guidance formelle pour un KEM hybride IND-CCA2 incluant ML-KEM.

**Décision :** KEM hybride **X25519 + ML-KEM-768** (façon X-Wing). Pour les signatures du log : **hash-based** (voir Q4/Q5).

### Q4 — Maturité des libs PQC (et statut d'audit)

| Lib / cible | Statut juin 2026 | Note |
|---|---|---|
| **liboqs** | « NE PAS utiliser en production / pour données sensibles » (avertissement officiel maintenu) | Référence d'expérimentation. oqs-provider **non FIPS-validé**. |
| **OpenSSL 3.5+ / oqs-provider** | PQC livré, stabilisation prod en cours | Validation FIPS 140-3 des modules PQC attendue 2026-2027. |
| **ML-KEM (impl. formellement vérifiées)** | Code C vérifié mémoire/type (CBMC) ; routines AArch64 vérifiées (HOL-Light) | Bon signal de maturité. |
| **Rust PQC** | « The belt is vacant » (Project Eleven) — pas encore de lib Rust PQC dominante auditée | `pqcrypto` **pas audité indépendamment** ; `liboqs-rust` expose ML-KEM/ML-DSA. |
| **`@noble/post-quantum`** (déjà utilisé dans Protocol-01) | ML-KEM-768 standardisé, JS/TS | Pratique pour le client WASM/CLI. |

**Décision :** prototype sur `@noble/post-quantum` (ML-KEM-768) côté client/CLI pour aller vite, et noter dans les limites que la prod exigerait des modules FIPS-validés. Ne **pas** se limiter à liboqs.

### Q5 — Où exactement la primitive classique est-elle remplaçable, sans casser la chaîne TPM

Le flow Anthropic : **TPM** (mesure boot → hash) → **keyserver** (vérifie → libère clés) → **loader** signé CI (seul à toucher le cleartext). Le papier **ne traite ni PQC, ni vérification côté user, ni transparency log** (confirmé sur la page de recherche Anthropic — gaps explicites).

Points d'intervention, du moins au plus profond :

| Point | Aujourd'hui | Intervention | Casse la chaîne TPM ? |
|---|---|---|---|
| Quote TPM racine | RSA/ECC (hardware) | — (hors scope, voir Q2) | N/A |
| **Binding clé de session** | KEM classique (probable) | **X25519+ML-KEM-768**, lié dans le `report_data` : `H(nonce ‖ pubkey_MLKEM ‖ measurement)` | Non — au-dessus du TPM |
| **Mesure du loader → autorisation** | hash comparé à une *reference value* privée du keyserver | **Exiger l'inclusion** de la mesure dans un **log public PQ** avant release | Non — ajoute une condition |
| **Signature de l'autorisation / STH** | classique | **SLH-DSA / XMSS-LMS (hash-based)** | Non |
| **Vérification finale** | keyserver uniquement | **+ reçu vérifié côté client** (attestation + binding + preuve d'inclusion + STH) | Non — ajoute un vérifieur |

Le pattern de binding HNDL-safe (`report_data = SHA256(nonce ‖ ML-KEM pubkey)` dans un quote TDX) est **déjà connu/déployé** ailleurs → on le réutilise tel quel, la nouveauté n'est pas là.

---

## 3. Schéma du flow annoté

```
                                          ┌─────────────────────────────────┐
                                          │   LOG DE TRANSPARENCE PUBLIC     │
                                          │   (append-only Merkle)           │
                                          │   feuilles = measurements de     │
                                          │   builds de loader attestés      │
                                          │   STH signé  [PQ: SLH-DSA/XMSS]  │ ◄── auditeurs +
                                          └───────────────┬─────────────────┘     gossip STH (anti split-view)
                                                          │ preuve d'inclusion
                                                          │
   ┌──────────┐   quote     ┌───────────────┐  vérifie   │   ┌───────────────────────────┐
   │  TPM     │── boot ────►│   LOADER       │── Evidence ┼──►│   KEYSERVER (Verifier+RP)  │
   │ [CLASSIQUE: racine     │   (Attester)   │            │   │  release la clé SSI :      │
   │  RSA/ECC, hardware,    │                │            │   │   (1) attestation valide   │
   │  hors scope]           │                │◄── clé ────┤   │   (2) measurement INCLUS   │
   └──────────┘             └───────┬────────┘ encapsulée │   │       dans le log public   │
                                    │          [PQ: ML-KEM]│   └───────────────────────────┘
                                    │ déchiffre
                                    ▼
                              donnée test
                                    │
              ┌─────────────────────┴───────────────────────┐
              │  REÇU DE SESSION (renvoyé à l'utilisateur)   │
              │   { attestation,                             │
              │     binding  H(nonce ‖ ML-KEM pubkey ‖ msmt),│ ◄── [NOUVEAU] vérifié
              │     preuve d'inclusion Merkle,               │     CÔTÉ CLIENT, en PQ,
              │     STH signé [PQ] }                         │     CLI/WASM, < 5 min
              └──────────────────────────────────────────────┘

  Légende :  [CLASSIQUE] = inchangé / hors scope   [PQ] = post-quantique   [NOUVEAU] = apport de l'artefact
```

**Frontière classique → PQ → transparence :** la racine TPM reste classique (hardware). Tout ce qui est *au-dessus* — binding de clé, signature du log, preuve d'inclusion — passe en PQ. Et la **nouveauté** est la boucle de droite (log public + inclusion exigée au release) et du bas (reçu vérifié par l'utilisateur).

---

## 4. Carte des assets Protocol-01 à extraire

> ⚠️ **Correction (voir `DECISIONS.md` ADR-002).** Le « ~70 % extraction » ci-dessous était calculé sur les assets **TypeScript**. Le MVP étant décidé en **Rust**, la réalité tombe à ~**35–45 %** extraction-as-reference (port Anchor→std, pas copier-coller) : ML-KEM devient un crate externe, WOTS+/Merkle sont à porter. La table TS ci-dessous est conservée pour mémoire ; la table Rust faisant foi est dans `DECISIONS.md`.

| Besoin de l'artefact | Asset Protocol-01 (TS, pour mémoire) | Chemin |
|---|---|---|
| Le log append-only lui-même | Merkle tree incrémental + Poseidon | `packages/privacy-toolkit/src/merkle/incrementalTree.ts`, `stark/src/poseidon/` |
| Reconstruction de preuves d'inclusion | proof-from-subtrees | `packages/privacy-toolkit/src/merkle/proofFromSubtrees.ts` |
| Signature hash-based du STH | WOTS+ (brique de XMSS/LMS) | `programs/p01_quantum_vault/`, `docs/quantum-resistance.md §2.3` |
| Binding clé HNDL-safe | ML-KEM-768 hybride (`@noble/post-quantum`) | `packages/specter-sdk/src/relay/encrypt.ts` |
| Liaison session | HKDF-SHA256 avec transcript binding | `packages/privacy-sdk/src/modules/stealth.ts` |
| (Option) preuve d'inclusion en STARK, vérif navigateur | STARK Winterfell + FRI verifier + prover WASM | `stark/`, `programs/p01_stark_verifier/`, `packages/stark-prover/` |
| Harness CLI / bench | binaires `gen_proof`, `probe_ood` + scripts | `stark/src/bin/`, `scripts/` |

> ⚠️ Licence : Protocol-01 est *ALL RIGHTS RESERVED*. Décider explicitement (Phase 1) du statut de licence du code **extrait** vers ce repo standalone. À trancher avant de publier.

---

## 5. MVP cible (Phase 1, pour mémoire — pas codé)

CLI d'abord. Démontre :
1. **Build loggé + attesté** → keyserver libère la clé (ML-KEM) → client vérifie inclusion + STH PQ → ✅.
2. **Build « fantôme » non loggé** (attaque ciblée/split-view simulée) → pas de preuve d'inclusion → **client refuse** → ❌.
3. **Bench** : taille preuve d'inclusion, tailles sig PQ vs classique (ECC ~64 B ; ML-DSA-65 ~3.3 KB ; SLH-DSA ~17–50 KB ; ML-KEM-768 ct ~1.1 KB), latence vérif client.

**Critère de réussite :** un dev sécu lance la démo en < 5 min et voit le client **refuser** un loader compromis *que l'attestation classique seule aurait accepté*.

---

## 6. Honnêteté sur la nouveauté (garde-fou)

**Existe déjà :** binding KEM-PQ dans un quote (Chutes, TDX `report_data`) ; transparence CC conceptuelle (arXiv 2409.03720) ; attestable builds + log (arXiv 2505.02521) ; attestation PQ XMSS/LMS (papiers) ; CT/Rekor (Merkle + STH, **classiques**, supply-chain pas session).

**N'existe pas comme artefact qui tourne :** la **combinaison** — log de transparence **post-quantique**, **lié à la session d'inférence live**, avec **reçu vérifié côté utilisateur final**, démo reproductible. La valeur est dans l'exécution de la combinaison, pas dans une idée inédite.

**Limites à écrire noir sur blanc :** racine TPM classique non couverte ; tout est **simulé** (mock TPM/TDX quote) ; libs PQC non FIPS-validées en prototype ; gossip anti-split-view esquissé, pas un réseau d'auditeurs réel.

**Cadrage de la valeur (voir `DECISIONS.md` ADR-006).** Un *measurement* est le hash d'un build opaque (source loader non publique) → la transparence ne prouve PAS qu'un build est honnête. Ce qu'elle prouve : **non-équivocation** (un seul historique public) + **responsabilité tamper-evident** (un backdoor découvert plus tard est non-répudiable). La force « mordante » réelle exige des **builds reproductibles** (SLSA/in-toto) — hors-scope MVP, documenté comme dépendance. Règle de pitch : « ils ne peuvent plus mentir en secret ni réécrire l'histoire », jamais « tu sauras si c'est piégé ».

---

## 7. Backlog (angles secondaires, pas maintenant)

- **B — Token-metering PQ prouvable** : reçu STARK signé des tokens servis (le stack STARK de Protocol-01 est idéal). Histoire « aide Anthropic » plus faible.
- **C — Non-substitution de modèle liée à l'attestation** : gap réel (« Are You Getting What You Pay For », arXiv 2504.04715) mais plus dur et n'exploite pas les assets hash-based.

---

## 8. Sources

- Anthropic & Pattern Labs — *Confidential Inference via Trusted Virtual Machines* : https://www.anthropic.com/research/confidential-inference-trusted-vms
- RFC 9334 — RATS Architecture : https://www.rfc-editor.org/info/rfc9334/
- RFC 6962 — Certificate Transparency : https://www.rfc-editor.org/rfc/rfc6962.html
- Confidential Computing Transparency (framework) : https://arxiv.org/html/2409.03720
- Attestable builds via TEE : https://arxiv.org/html/2505.02521v1
- X-Wing hybrid KEM (IETF draft) : https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
- TLS 1.3 hybrid ECDHE-MLKEM (IETF draft) : https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
- Infineon TPM PQ pour Physical AI / Jetson Thor : https://silicon-saxony.de/en/infineon-security-for-physical-ai-with-certified-tpm-solution-and-quantum-resistant-hardware-security-for-nvidia-robotics-platform-jetson-thor
- SealSQ QVault TPM (FIPS 203/204) : https://www.sealsq.com/products/secure-element/tpm/qvaulttpm
- Stateless PQ remote attestation IoT (TPM+DICE), IEEE : https://ieeexplore.ieee.org/document/11354774/
- liboqs releases / statut : https://github.com/open-quantum-safe/liboqs/releases
- State of PQC in Rust (Project Eleven) : https://www.projecteleven.com/blog/the-state-of-post-quantum-cryptography-in-rust-the-belt-is-vacant
- OpenSSL PQC status 2026 : https://quantumsequrity.com/blog/openssl-pqc-status-2026
- Chutes — E2E encrypted inference with PQC : https://chutes.ai/news/end-to-end-encrypted-ai-inference-with-post-quantum-cryptography
- CSA — Harvest Now Decrypt Later: Quantum Risk to AI Infrastructure : https://labs.cloudsecurityalliance.org/research/ai-infrastructure-post-quantum-harvest-now-decrypt-later-v1/
- zkAgent (verifiable agent execution) : https://eprint.iacr.org/2026/199
- DeepProve (verifiable end-to-end LLM inference) : https://eprint.iacr.org/2026/1112
- Auditing Model Substitution in LLM APIs : https://arxiv.org/html/2504.04715
- IETF draft — AI Model Lifecycle Attestation : https://datatracker.ietf.org/doc/draft-sharif-ai-model-lifecycle-attestation/

---

## 9. Prochaine action

→ ~~Trancher la licence + figer le périmètre MVP~~ **FAIT** (voir `DECISIONS.md` : licence **MIT**, langage **Rust**, MVP figé). Phase 1 débloquée : prototype CLI Rust. Premier jalon = couche signature hash-based du STH (trancher SLH-DSA vs XMSS, ADR-003).
