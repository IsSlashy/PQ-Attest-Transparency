# PQ-Attest-Transparency

A post-quantum **transparency layer** for confidential AI inference: an append-only,
client-verifiable record of which loader builds a confidential-inference service runs —
so a provider cannot *secretly* serve a targeted, backdoored build.

Think *Certificate Transparency, for confidential inference, post-quantum, verified by the end user.*

> **Status: M0–M4 done — a reference MVP. The PQ primitives are real (not placeholders), but UNAUDITED.**
> STH signed with **SLH-DSA** (FIPS 205); Merkle log with RFC 6962 **inclusion + consistency**
> proofs; HNDL-safe session binding with **X-Wing** (X25519+ML-KEM-768); **anti-split-view by
> independent witness co-signing** (no blockchain); a **client-side receipt verifier that
> compiles to WebAssembly**. M5 (bench + threat model) in progress.
>
> **Caveats up front (full list in [`THREAT-MODEL.md`](./THREAT-MODEL.md)):** all PQ crates
> (`fips205`, `x-wing`, `ml-kem`) are maintained and NIST-vector-tested but **independently
> UNAUDITED** and not FIPS-validated; the **hardware attestation quote is MOCKED** (no real root
> of trust in the demo); and the value claim is conditional on **reproducible builds** and an
> **operated witness federation**, neither of which this single-machine MVP delivers. It is
> architecturally Web2-deployable — no blockchain required — but a reference, not a drop-in.
> Roadmap/decisions: [`DECISIONS.md`](./DECISIONS.md). Research: [`RESEARCH.md`](./RESEARCH.md).

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
  in real time.
- ❌ **The hardware root of trust is MOCKED.** `MockQuoteProvider` computes the binding
  honestly but performs no real attestation — there is no TDX/TPM quote and no hardware
  signature in the demo. Everything downstream assumes a sound, hardware-signed quote that a
  real deployment must supply (see [`THREAT-MODEL.md`](./THREAT-MODEL.md) §3).

**Load-bearing dependency:** tamper-evident accountability only *bites* if loader builds are
**reproducible** (SLSA/in-toto), so a logged measurement maps back to auditable source. That is
documented here, **not built** — without it, a discovered hash is undeniable as *served*, but
cannot be tied to source code.

Pitch rule: *"they can no longer lie in secret or rewrite history"* — never *"you'll know if it's backdoored."*

## Architecture (every trust boundary is a trait: mock now, real path documented)

- `QuoteProvider` — attestation quote. **Mocked** (`MockQuoteProvider`): computes the binding
  honestly but is NOT a real root of trust. Real path: a TDX/TPM quote whose `report_data` binds
  `H(nonce ‖ ML-KEM pubkey ‖ measurement)` and whose hardware signature the client verifies.
- `SthSigner` — signs the log's Signed Tree Head with **SLH-DSA** (FIPS 205) via the `fips205`
  crate (maintained, NIST-vector-tested, **NOT independently audited**).
- `Anchor` — makes history non-equivocal. `WitnessAnchor` (M4): independent witness co-signing,
  no blockchain. (`LocalAnchor` is an M0 stand-in.) Optional: `ChainAnchor` (on-chain root;
  removes the need to bootstrap a witness federation — *not* a speed argument).

## Prerequisites

Rust (stable) for the CLI and tests. For the browser demo also: `wasm-pack`
(`cargo install wasm-pack`), Node 18+, and Python 3.

## Run the CLI demo

```bash
cargo run -p pqtl-cli --bin pqtl-demo   # ✅ logged+HNDL-safe / ❌ ghost build / ❌ rewrite / ❌ split-view
cargo test                              # inclusion 1..33, consistency, SLH-DSA, X-Wing KEM, witnesses, attacks
cargo run --release -p pqtl-cli --bin pqtl-bench   # size/latency table (see BENCHMARKS.md)
```

(The `pqtl-demo` console output is in French; an English walkthrough is in `THREAT-MODEL.md` §5.)

## Run the browser verifier (M3)

The receipt verifier compiles to WASM and runs entirely client-side:

```bash
sh scripts/build-web-demo.sh            # emits a sample receipt + builds web/pkg
cd web && python3 -m http.server 8080   # (or `python`) then open http://localhost:8080
```

The honest receipt verifies ✅; the "Tamper" button flips one byte of the SLH-DSA
signature and it fails ❌. Headless proof (no browser):

```bash
wasm-pack build crates/pqtl-wasm --target nodejs --dev --out-dir pkg-node
cargo run -p pqtl-cli --bin pqtl-emit
node scripts/wasm-smoke.cjs             # honest=accept, tampered=reject, split-view=reject
```

## Cost (the PQ tax)

Full numbers in [`BENCHMARKS.md`](./BENCHMARKS.md). Headline: a receipt is ~10 KB (the STH
signature alone is ~123× an Ed25519 signature — 64 B → 7856 B), but **client-side verification
stays sub-millisecond (~0.14 ms)**. The one expensive operation, SLH-DSA signing (~130 ms), is
paid once per STH by the operator, never by the client per request. PQ safety costs **bytes and
operator sign-time, not user-facing latency.**

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

## Documents

- [`THREAT-MODEL.md`](./THREAT-MODEL.md) — what is proven vs assumed vs mocked (read this).
- [`BENCHMARKS.md`](./BENCHMARKS.md) — the "PQ tax": sizes vs classical, and latencies.
- [`DECISIONS.md`](./DECISIONS.md) — ADRs + roadmap. [`RESEARCH.md`](./RESEARCH.md) — Phase 0.
- [`docs/EXTRACTION.md`](./docs/EXTRACTION.md) — Protocol-01 reuse map + crate selection.

## License

MIT — see [`LICENSE`](./LICENSE). Some logic is ported (as reference) from the author's
Protocol-01; only code copied into this repo is MIT.
