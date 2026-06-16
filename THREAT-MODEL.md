# THREAT-MODEL.md — PQ-Attest-Transparency

> The honest statement of what this artifact defends, what it does not, and where the
> simulation ends. Read alongside `DECISIONS.md` (ADR-006 is the governing decision) and
> `RESEARCH.md` §6. The pitch rule from ADR-006 binds this whole document: *"they can no
> longer lie in secret or rewrite history"* — never *"you will know if it is backdoored."*
>
> Date: 2026-06-16. Status: M0–M4 complete (SLH-DSA STH, RFC 6962 inclusion + consistency,
> X-Wing session binding, witness anti-split-view, WASM verifier); single-machine simulation.

---

## 1. Overview — the gap in confidential inference

Confidential inference as deployed today (e.g. Anthropic & Pattern Labs, *Confidential
Inference via Trusted Virtual Machines*, 2025) proves that a serving environment is sane
**to the provider's own keyserver**. In RATS terms (RFC 9334) the loader is the *Attester*,
but the *Verifier* and the *Relying Party* are the same entity — the provider. The end user
is none of the three roles, and therefore verifies nothing (`RESEARCH.md:38-40`).

This is fine against a provider that is honest toward everyone. It is structurally useless
against a provider that is compromised, compelled, or malicious **toward one specific user**.
Such a provider can build a backdoored loader, sign it with its own legitimate CI, pass its
own attestation, and serve that one user a different build than everyone else — a *targeted /
split-view* attack. Classic attestation cannot catch this, because a server that is honest
toward its own verifier stays honest toward itself by construction (`README.md:19-25`).

This is exactly the problem Certificate Transparency (RFC 6962) solved for TLS certificate
authorities: a CA could mis-issue a certificate to one victim, and no outside party could
see it. CT's answer was not "detect bad certificates" — it was to force every issued
certificate into a public, append-only, non-equivocable log, so mis-issuance becomes
*undeniable after the fact*. This project transposes that mechanism to confidential-inference
loader builds, post-quantum, and verified by the end user.

The honest value claim is therefore **non-equivocation plus tamper-evident accountability**,
NOT backdoor detection. A logged measurement is the hash of an *opaque* build; seeing it in
the log does not tell you the build is honest (`README.md:35-38`, ADR-006 at `DECISIONS.md:67`).
What it buys is that the provider can no longer show `measurement_good` to you and
`measurement_evil` to your neighbour, and can no longer secretly rewrite which build it served.

---

## 2. Actors & assets

**Actors.**

- **End user / client verifier.** Holds only the log operator's public verifying key, the
  trusted-witness public keys, and an expected per-session nonce. Runs the receipt verifier
  (`verify::verify_receipt`, `lib.rs:844`), which is RNG-free and compiles to WASM
  (`crates/pqtl-wasm`). This is the party the whole artifact exists to empower.
- **Provider (log operator + keyserver).** Operates the transparency log, signs Signed Tree
  Heads with SLH-DSA (`log::TransparencyLog::signed_tree_head`, `lib.rs:713`), and runs the
  keyserver release policy (`keyserver_issue`, `main.rs:29`) that releases a session key only
  if the attested measurement is already in the public log. This actor is the *adversary* in
  the core threat: assumed potentially compromised or compelled toward a targeted user.
- **Independent witnesses.** Co-sign STHs after checking an RFC 6962 consistency proof, and
  refuse to co-sign a forked/rewritten history (`witness::Witness::cosign`, `lib.rs:477`).
  They are the Web2 source of non-equivocation (ADR-004).
- **Hardware root (TDX/TPM).** In a real deployment, produces the attestation quote whose
  `report_data` binds the session. **In this artifact it is mocked** — see §3.
- **Quantum-equipped adversary (future).** A harvest-now-decrypt-later (HNDL) attacker who
  records ciphertexts today to decrypt once a cryptographically-relevant quantum computer
  exists; and, post-CRQC, an active forger of classical signatures.

**Assets.**

- **Session confidentiality** of the user's inference data, which must survive HNDL.
- **Integrity and non-equivocation of the served-build history** — the public record of which
  loader measurements were served, to whom, when.
- **The session receipt** (`Receipt`, `lib.rs:100`): quote, nonce, KEM public key, KEM
  ciphertext, inclusion proof, signed tree head. This is the central client-verifiable object.
- **Signing keys**: the operator's SLH-DSA key, each witness's SLH-DSA key, and the client's
  X-Wing decapsulation secret (which never leaves the client, `lib.rs:372-373`).

---

## 3. Trust boundaries — and the MOCK-TPM root made explicit

The design discipline (ADR, `DECISIONS.md:84`) is that *every trust boundary is a trait with
a mock implementation and a documented real path*, so the simulated parts are explicit and
swappable. The three boundaries are `QuoteProvider`, `SthSigner`/`SthVerifier`, and `Anchor`
(`lib.rs:159`, `:167`, `:180`).

**The hardware root of trust is MOCKED, and this is the single most important caveat in this
document.** `MockQuoteProvider::quote` (`lib.rs:191-197`) does not perform attestation. It
simply computes `report_data = H(DOMAIN ‖ nonce ‖ kem_pubkey ‖ measurement)` honestly. In a
real deployment this value would be produced and signed by hardware (TDX/TPM) whose firmware
measured the *actually-loaded* image; here it is recomputed in software from fields the caller
supplies. There is **no real quote, no hardware signature, and therefore no real root of
trust** in the demo (`RESEARCH.md:57`, `:168`).

Two consequences follow, and a skeptic is right to lead with them:

1. **The mock cannot equivocate, so it cannot demonstrate the hard part.** The defended threat
   is "a provider serves a measurement that differs from what `report_data` binds." That
   divergence is constrained *only* by a real hardware quote. A malicious software quote
   provider could return any `report_data` it wanted. The demo's "attack detected" outcomes in
   scenarios 2 and 3 are therefore guaranteed by construction against a software provider, not
   earned by exercising a real attestation path.

2. **The binding check in the verifier is tautological against a software quote.**
   `verify_receipt` step 1 (`lib.rs:850-854`) re-derives the expected `report_data` from the
   receipt's own `nonce`, `kem_pubkey`, and `measurement`, using the same `compute_report_data`
   the mock used to produce it. It will reject an attacker who *forgets* to recompute the hash,
   but it has no independent oracle for whether the bound measurement is the one the hardware
   actually loaded. The binding check only becomes meaningful when a real, hardware-signed quote
   replaces the mock and the verifier additionally checks the hardware signature over
   `report_data` — which this artifact does not do.

The classical hardware root is **explicitly out of scope** (`DECISIONS.md:98`,
`RESEARCH.md:52-57`): a deployed TPM/TDX quote is signed in RSA/ECC, fixed in silicon, and
cannot be made post-quantum after the fact. This project's PQ and transparency layers sit
*above* that root. Everything downstream of the quote assumes the quote is sound; nothing here
defends the attestation root itself, and a quantum-classical TPM forgery is unaddressed.

The other two boundaries are real in M0–M4: `SthSigner`/`SthVerifier` is real SLH-DSA
(`slh` module, `lib.rs:242`), and `Anchor` has a real witness-quorum implementation
(`WitnessAnchor`, `lib.rs:503`). The `PlaceholderSigner` (`lib.rs:203`) and `LocalAnchor`
(`lib.rs:226`) remain as M0 stand-ins used only in some tests and the simplest demo path; the
placeholder signer is a keyed SHA-256 tag, symmetric and not a signature, and must never be
read as cryptographic strength.

---

## 4. Security properties — guarantee, mechanism, and limits of each

### 4.1 Non-equivocation

**Guarantees.** The provider commits to one public history. It cannot present
`measurement_good` to you and `measurement_evil` to your neighbour and have both produce
verifying receipts, because a verifying receipt requires the measurement to be included in a
*signed, witness-anchored* root, and the witnesses will anchor only one root per (size).

**Mechanism.** A receipt carries an SLH-DSA-signed STH (`SignedTreeHead`, `lib.rs:72`) and an
RFC 6962 inclusion proof. `verify_receipt` checks the STH signature (step 2, `lib.rs:856-859`),
the inclusion of the measurement in that signed root (step 3, `lib.rs:861-863`), and that the
root was anchored by the witness quorum (step 4, `lib.rs:865-867`). A split-view fork would
need a *second* validly signed-and-anchored root, which the anchoring step denies.

**Does NOT guarantee.** It does not tell you the single logged build is honest — only that
there is one history, not two. It does not guarantee anyone is *watching* the log: like CT,
non-equivocation only "bites" when there are active witnesses/monitors comparing what they see
(`README.md` honesty section; CT's own bite depends on monitors). And, as a known limitation,
the client's anchor set is keyed on the **root only**, not on `(tree_size, root)`
(`LocalAnchor` at `lib.rs:229-236`; `WitnessAnchor::is_anchored` at `lib.rs:542-550`), even
though the witness cosignature itself binds both size and root (`cosignature_bytes`,
`lib.rs:146`). Anchoring on the `(tree_size, root)` pair would be tighter.

### 4.2 Tamper-evident accountability

**Guarantees.** If a backdoored build is ever discovered, the log proves
non-repudiably that it was served — to everyone able to verify, at the recorded tree size.
The provider cannot later deny having served it, because the measurement sits under an
SLH-DSA-signed, witness-cosigned root.

**Mechanism.** Same signed-STH + inclusion-proof chain as above; the SLH-DSA signature is the
non-repudiation anchor and the witness cosignatures make the committed root one the provider
cannot disown.

**Does NOT guarantee — and this is load-bearing.** Tamper-evidence only *bites* if a logged
measurement can be mapped back to **reviewable source**, which requires reproducible builds
(SLSA / in-toto provenance). That dependency is **documented here, not built** (ADR-006 at
`DECISIONS.md:69`; `README.md:37-38`). Without it, a discovered hash is undeniable as *a hash
that was served*, but still cannot be tied to source code — so "accountability" is real for
the fact of serving and conditional for the substance. This is a precondition of the entire
value claim, not a footnote.

### 4.3 HNDL-safe session binding

**Guarantees.** Recovering the session key requires breaking *both* X25519 and ML-KEM-768, so
a ciphertext harvested today is not decryptable by a future quantum adversary. The session key
is transcript-bound to the attested measurement, so a key release cannot be silently retargeted
to a different build.

**Mechanism.** X-Wing (X25519 + ML-KEM-768, draft-connolly-cfrg-xwing-kem) via the `x-wing`
crate (`kem` module, `lib.rs:329`). The client's public key is committed in `report_data`; the
keyserver encapsulates against it (`encapsulate`, `lib.rs:403`); the client decapsulates
(`lib.rs:394`); both derive the session key with
`HKDF(ikm = xwing_ss, info = H("pqtl:session-v1" ‖ nonce ‖ ciphertext ‖ measurement))`
(`derive_session_key`, `lib.rs:411-423`). A tampered ciphertext yields a divergent secret
(ML-KEM implicit rejection), so the channel fails closed (test at `lib.rs:1061-1066`).

**Does NOT guarantee — and a real gap in the verifier.** `verify_receipt` does **not validate
`kem_ciphertext` at all** (`lib.rs:844-869`): the ciphertext is not committed into `report_data`,
its length is not checked, and `derive_session_key` is never invoked on the verify path. A
receipt carrying a garbage (or empty) `kem_ciphertext` still verifies `Ok` — indeed the demo's
forged receipt and several tests pass `kem_ciphertext: Vec::new()` (`main.rs:124`,
`lib.rs:932`). The verifier likewise never checks that `kem_pubkey` has length
`PUBLIC_KEY_LEN` (`lib.rs:851`, the binding is hashed but unvalidated for length). Closing this
requires either committing the ciphertext into `report_data` or length-checking both
`kem_pubkey` and `kem_ciphertext` in `verify_receipt`. Until then, "the receipt verified" does
**not** mean "a sound HNDL-safe session key was established" — only that the binding hash and
the log proofs are consistent. The HNDL property is real for the *channel* exercised in
`main.rs` / tests, but is not enforced by the client receipt check.

There is also no replay/freshness state: freshness is the caller's duty (the verifier checks
the receipt's nonce equals an expected nonce, `lib.rs:852`, but holds no used-nonce set), and
`pqtl-emit` ships a fixed demo nonce (`emit.rs:20`). A real deployment must supply a fresh,
single-use nonce per session.

### 4.4 Anti-split-view via witnesses

**Guarantees.** A root becomes trusted only once a quorum (`threshold`) of *distinct* known
witnesses has validly cosigned it. An honest witness refuses to cosign a forked/rewritten
history, so a split-view fork cannot reach the threshold and the client rejects its root with
`NotAnchored`.

**Mechanism.** `Witness::cosign` (`lib.rs:477-498`) refuses unless a supplied RFC 6962
consistency proof shows the new tree extends the one the witness last saw. `WitnessAnchor::ingest`
(`lib.rs:520-539`) counts distinct valid cosignatures and trusts the root only at or above
threshold; `WitnessAnchor::anchor` is a deliberate no-op (`lib.rs:543-546`) so a root can never
become trusted by bare assertion. This is the Web2 core of ADR-004: it removes the need to
bootstrap or operate a federation only in the sense that it requires no blockchain — it still
requires the federation itself.

**Does NOT guarantee.** Witnesses are a trust assumption, not a proof: if `threshold`-or-more
witnesses collude (or are the same compromising party), they can cosign a fork and the client
will accept it. Security degrades to the honesty of the quorum. Crucially, **no real witness
network is run** — there is no gossip protocol, no independent operators, no network transport.
The whole thing is simulated in-process (the demo generates three witnesses on one machine,
`main.rs:166`). The anti-split-view property is *mechanically* demonstrated but not
*operationally* delivered; a real deployment must recruit and independently operate witnesses
(out of scope, `DECISIONS.md:98`).

### 4.5 Append-only / consistency

**Guarantees.** History cannot be rewritten without detection: any size-`m` tree must be a
prefix of any later size-`n` tree, or the consistency check fails. A provider that secretly
swapped an earlier leaf produces a different historical root that the honest proof cannot
reconcile.

**Mechanism.** RFC 6962 consistency proofs (`ConsistencyProof`, `lib.rs:91`;
`verify_consistency`, `lib.rs:772-817`), validated for sizes 1..33 and in an explicit
history-rewrite test (`lib.rs:996`, `:1025`). Witnesses use the same check before cosigning, so
append-only is enforced both at verification time and at anchoring time.

**Does NOT guarantee.** The log is **not incremental** — it rebuilds the tree from stored leaf
hashes on every query, O(n) per proof rather than O(log n) (`lib.rs:557-562`,
`mth`/`path`/`root` at `lib.rs:582`, `:594`, `:695`). This is a performance limitation, not a
soundness one. One soundness-adjacent edge: `verify_consistency` for `first_size == 0` returns
on an empty path **without checking either root** (`lib.rs:786-789`), accepting arbitrary roots
as "consistent with the empty tree." It is a `pub fn` and currently unreachable (the prover
rejects `first_size == 0` at `lib.rs:727`), but a defensive fix would also require `first_root`
to equal the empty-tree root. Separately, the empty-tree sentinel uses an unkeyed string tag
(`b"pqtl:empty-tree"`, `lib.rs:584`); string tags start at `0x70` and are disjoint from the
`0x00`/`0x01` leaf/node domain separators, so there is no collision — cosmetic only.

---

## 5. Attacks defended vs explicitly out of scope

**Defended (within the simulation).**

- *Targeted ghost build / split-view.* A measurement not in the log yields no inclusion proof;
  an honest keyserver refuses release, and even a forged receipt reusing an honest leaf's
  inclusion proof is caught client-side with `InclusionInvalid` (scenario 2, `main.rs:108-132`).
- *History rewrite.* A secretly-swapped earlier leaf fails the consistency check (scenario 3,
  `main.rs:134-162`).
- *Forked history presented for anchoring.* Honest witnesses refuse to cosign; the fork never
  reaches threshold and the client rejects it as `NotAnchored` (scenario 4, `main.rs:164-207`).
- *Tampered STH signature.* The SLH-DSA verify fails with `SthSignatureInvalid` (the WASM demo
  "Tamper" button flips a signature byte, `README.md:69`).
- *HNDL on the session channel.* X-Wing makes a harvested ciphertext require breaking both
  X25519 and ML-KEM-768 — for the channel exercised in code, subject to the verifier gap in §4.3.

**Explicitly out of scope.**

- *The hardware attestation root.* Mocked; classical TPM/TDX quote unmodeled; quantum-classical
  TPM forgery unaddressed (§3; `DECISIONS.md:98`).
- *Whether a logged build is honest / backdoor detection.* Out of scope by ethos — transparency
  proves non-equivocation and accountability, not honesty (ADR-006).
- *A real witness/gossip network.* Only sketched; no operators, no transport, no gossip
  (`DECISIONS.md:98`, `RESEARCH.md:168`).
- *Reproducible builds.* Documented as the dependency that makes tamper-evidence bite; not built.
- *STARK inclusion proofs and on-chain `ChainAnchor`.* Optional, post-MVP (`DECISIONS.md:82`).
- *Side channels, supply-chain compromise of the build toolchain itself, denial of service,
  and key-management/HSM operation.*

---

## 6. Assumptions & residual risks

- **Unaudited PQ crates.** `fips205`, `x-wing`, and the `ml-kem` it pulls in are maintained and
  NIST-vector-tested but **NOT independently audited and not FIPS-validated** (`lib.rs:248`,
  `:339`; `EXTRACTION.md:62-63`). Only libcrux's ML-KEM core is formally verified, and it is not
  the crate used here. Production use requires a clean cryptographic review. (Note: the README
  currently calls `fips205` "an audited crate" at `README.md:46-47`; this contradicts every
  other file and is an error to fix — the crate is unaudited.)
- **The reproducible-build dependency.** Transparency only bites if logged measurements map to
  reviewable source via SLSA/in-toto provenance. Documented, not built (§4.2). Without it, the
  accountability claim is real for *the fact of serving* but cannot reach *the substance of what
  was served*.
- **Witness collusion ≥ threshold.** Anti-split-view degrades to the honesty of the witness
  quorum; a colluding quorum can anchor a fork (§4.4). The MVP assumes independent, honest
  witnesses but does not enforce or even operate that independence.
- **No real network; single-machine simulation.** There is no gossip, no witness federation, no
  real keyserver or loader, and no real hardware. The demo runs entirely in one process. Every
  "attack blocked" outcome is demonstrated against simulated components, and the mock quote
  provider cannot itself equivocate (§3).
- **SLH-DSA being stateless is a deliberate safety choice.** Choosing SLH-DSA (FIPS 205) over
  stateful XMSS/LMS removes the key-reuse footgun: with a stateful scheme, reusing a one-time
  leaf index enables forgery — catastrophic for a multi-signer append-only log. Statelessness
  costs signature size (7856 bytes for SHA2-128s) but eliminates that class of operational
  failure (ADR-003, `DECISIONS.md:36-41`).
- **Verifier gaps enumerated in §4.** `kem_ciphertext` is unvalidated by `verify_receipt`; no
  length pinning on `kem_pubkey`/`kem_ciphertext`; the anchor set ignores `tree_size`; no replay
  state; the `m=0` consistency edge accepts arbitrary roots (unreachable today). None breaks the
  demonstrated scenarios, but each is a real hardening item before any production claim.

---

## 7. Proven vs Assumed vs Mocked

| Property / component | Status | What that means here |
|---|---|---|
| RFC 6962 Merkle inclusion proofs | **Proven** | Real code, validated sizes 1..33 (`lib.rs:744`, `:886`). |
| RFC 6962 consistency / append-only | **Proven** | Real code + rewrite test (`lib.rs:772`, `:1025`); `m=0` edge and O(n) rebuild are caveats. |
| STH signing (SLH-DSA / FIPS 205) | **Proven** | Real `fips205` crate, sign/verify roundtrip (`lib.rs:242`, `:955`). Crate **unaudited**. |
| X-Wing session key agreement (HNDL) | **Proven (channel)** | Real `x-wing` crate; both sides agree, fails closed (`lib.rs:329`, `:1045`). Crate **unaudited**. |
| Receipt validates the KEM ciphertext | **NOT done** | `verify_receipt` ignores `kem_ciphertext`; garbage still verifies `Ok` (`lib.rs:844-869`). |
| Witness quorum / anti-split-view logic | **Proven (mechanism)** | Real cosign + threshold + fork refusal (`lib.rs:430`). |
| Non-equivocation against a fork | **Proven (mechanism)** | Holds given honest witnesses and the anchor check (`lib.rs:864-867`). |
| Hardware attestation quote / root of trust | **Mocked** | `MockQuoteProvider` computes the binding honestly; no real quote, cannot equivocate (`lib.rs:191`). |
| Binding check in `verify_receipt` | **Tautological vs mock** | Re-derives `report_data` from receipt fields; meaningful only with a real signed quote (`lib.rs:850`). |
| Real witness / gossip network | **Mocked** | In-process witnesses; no operators, no transport (`main.rs:166`). |
| Reproducible builds (provenance) | **Assumed / documented** | The precondition that makes tamper-evidence bite; not built (ADR-006). |
| Independent, honest witness quorum | **Assumed** | Collusion ≥ threshold breaks anti-split-view (§4.4). |
| Classical TPM root resists quantum forgery | **Assumed / out of scope** | Below this layer; not modeled (`RESEARCH.md:52-57`). |
| Fresh single-use session nonce | **Assumed (caller duty)** | No replay state; `pqtl-emit` uses a fixed nonce (`emit.rs:20`). |
| Backdoor detection | **Not claimed** | Out of scope by ethos: non-equivocation + accountability, never "you'll know if it's backdoored." |

---

*This document deliberately states what is proven, what is assumed, and what is mocked, in line
with ADR-006 and the project's honesty discipline. The defensible claim is that a provider can
no longer secretly serve divergent builds to different users, nor rewrite which build it served,
without it becoming undeniable — provided the log is actually watched, the witnesses are
independent, the builds are reproducible, and the mocked hardware root is replaced by a real
attested quote. None of those four conditions is delivered by this single-machine MVP; each is
named here so the gap between the demonstration and a deployment is explicit.*
