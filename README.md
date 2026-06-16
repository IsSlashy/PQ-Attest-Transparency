# PQ-Attest-Transparency

A post-quantum **transparency layer** for confidential AI inference: an append-only,
client-verifiable record of which loader builds a confidential-inference service runs —
so a provider cannot *secretly* serve a targeted, backdoored build.

Think *Certificate Transparency, for confidential inference, post-quantum, verified by the end user.*

> **Status: M0–M3 done. Cryptography is real end to end.**
> STH signed with **SLH-DSA** (FIPS 205); Merkle log with RFC 6962 **inclusion +
> consistency** proofs; HNDL-safe session binding with **X-Wing** (X25519+ML-KEM-768);
> and a **client-side receipt verifier that compiles to WebAssembly** and runs in the
> browser with no randomness and no network. Remaining: M4 witness co-signing, M5 bench.
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

## Run the CLI demo

```bash
cargo run -p pqtl-cli --bin pqtl-demo   # ✅ logged+HNDL-safe / ❌ ghost build / ❌ history rewrite
cargo test                              # 8 tests: inclusion 1..33, consistency, SLH-DSA, X-Wing, attack
```

## Run the browser verifier (M3)

The receipt verifier compiles to WASM and runs entirely client-side:

```bash
sh scripts/build-web-demo.sh            # emits a sample receipt + builds web/pkg
cd web && python -m http.server 8080    # then open http://localhost:8080
```

The honest receipt verifies ✅; the "Tamper" button flips one byte of the SLH-DSA
signature and it fails ❌. Headless proof (no browser):

```bash
wasm-pack build crates/pqtl-wasm --target nodejs --dev --out-dir pkg-node
cargo run -p pqtl-cli --bin pqtl-emit
node scripts/wasm-smoke.cjs             # honest=accept, tampered=reject, split-view=reject
```

## Layout

```
crates/
  pqtl-core/   types, trust-boundary traits, transparency log, client receipt verifier
               (RNG-free verify path; the `rng` feature gates keygen/sign/encapsulate)
  pqtl-cli/    pqtl-demo (CLI scenarios) + pqtl-emit (writes a sample receipt JSON)
  pqtl-wasm/   the receipt verifier compiled to WebAssembly (wasm-bindgen)
web/           index.html browser verifier + generated pkg/ (built by wasm-pack)
scripts/       build-web-demo.sh, wasm-smoke.cjs
```

## License

MIT — see [`LICENSE`](./LICENSE). Some logic is ported (as reference) from the author's
Protocol-01; only code copied into this repo is MIT.
