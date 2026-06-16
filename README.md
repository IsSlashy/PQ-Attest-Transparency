# PQ-Attest-Transparency

A post-quantum **transparency layer** for confidential AI inference: an append-only,
client-verifiable record of which loader builds a confidential-inference service runs —
so a provider cannot *secretly* serve a targeted, backdoored build.

Think *Certificate Transparency, for confidential inference, post-quantum, verified by the end user.*

> **Status: M0 — walking skeleton. All cryptography is a SHA-256 placeholder.**
> No real post-quantum primitive is wired yet. This milestone exists to prove the
> end-to-end wiring (binding → inclusion → signature → anchor) and the ✅/❌ demo.
> Roadmap and decisions: see [`DECISIONS.md`](./DECISIONS.md). Research: [`RESEARCH.md`](./RESEARCH.md).

## The problem (threat model — read this first)

Confidential inference (e.g. Anthropic's *Confidential Inference via Trusted VMs*, 2025)
proves a serving environment is sane **to the provider's own keyserver**. The end user
verifies nothing. So a provider that is compromised, compelled, or malicious toward one
user could serve *that user* a backdoored loader — signed by its own CI, passing
attestation — and **no outside party could detect it**. Classic attestation does not
defend against a *targeted / split-view* attack: a server honest toward its own verifier
stays honest toward itself.

## What this proves — and what it does not

This is the most important section, and we keep it honest (see `DECISIONS.md` ADR-006):

- ✅ **Non-equivocation.** The provider commits to **one** public history. It cannot show
  `measurement_good` to you and `measurement_evil` to your neighbour.
- ✅ **Tamper-evident accountability.** If a backdoored build is ever discovered, the log
  proves, non-repudiably, that it was served — to everyone, at that time.
- ❌ **It does NOT tell you a build is honest.** A measurement is the hash of an *opaque*
  build. Transparency makes a hidden backdoor **undeniable after the fact**, not detectable
  in real time. Real "biting" force additionally requires **reproducible builds**
  (SLSA/in-toto) — documented here as a dependency, out of scope for the MVP.

Pitch rule: *"they can no longer lie in secret or rewrite history"* — never *"you'll know if it's backdoored."*

## Architecture (every trust boundary is a trait: mock now, real path documented)

- `QuoteProvider` — attestation quote. M0: `MockQuoteProvider`. Real: TDX/TPM quote whose
  `report_data` binds `H(nonce ‖ ML-KEM pubkey ‖ measurement)` (HNDL-safe).
- `SthSigner` — signs the log's Signed Tree Head. M0: keyed SHA-256 tag. Real (M1):
  **SLH-DSA** (FIPS 205) via an audited crate.
- `Anchor` — makes history non-equivocal. M0: `LocalAnchor`. Web2 core (M4):
  `WitnessAnchor` (independent witness co-signing — deployable with no blockchain).
  Optional (M5): `ChainAnchor` (on-chain root; removes the need to bootstrap a witness
  federation — *not* a speed argument).

## Run the M0 demo

```bash
cargo run -p pqtl-cli       # the ✅ logged / ❌ ghost-build demo
cargo test                  # inclusion proofs (sizes 1..33) + receipt round-trip + attack
```

## Layout

```
crates/
  pqtl-core/   types, trust-boundary traits, transparency log, client receipt verifier
  pqtl-cli/    M0 demo driver (pqtl-demo)
```

## License

MIT — see [`LICENSE`](./LICENSE). Some logic is ported (as reference) from the author's
Protocol-01; only code copied into this repo is MIT.
