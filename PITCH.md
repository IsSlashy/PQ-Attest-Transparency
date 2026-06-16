# PITCH.md — what this is, in plain terms

> Factual by design. The work is meant to stand on its own; this file just states what it is,
> what it proves, and — explicitly — what it does not.

**One line.** A post-quantum *transparency layer* for confidential AI inference: an append-only,
user-verifiable record of which loader builds a provider runs, so a provider cannot *secretly*
serve a targeted, backdoored build — it makes such a build **undeniable, not undetectable**.
Certificate Transparency, transposed to confidential inference — post-quantum, verified by the
end user.

## The gap

Confidential inference (e.g. Anthropic's *Confidential Inference via Trusted VMs*, 2025) proves a
serving environment is sane **to the provider's own keyserver**. The end user verifies nothing. A
provider that is compromised, compelled, or malicious toward one user could serve *that* user a
backdoored loader — signed by its own CI, passing its own attestation — and no outside party could
detect it. Classic attestation does not defend a *targeted / split-view* attack: a server honest
toward its own verifier stays honest toward itself.

## What it does — and what it doesn't

It forces the served-build identity into a public, append-only, post-quantum, non-equivocable log,
and hands the end user a **receipt they verify themselves** (in the browser).

- ✅ **Non-equivocation** — the provider commits to one public history; it cannot show
  `measurement_good` to you and `measurement_evil` to your neighbour.
- ✅ **Tamper-evident accountability** — a backdoored build, once discovered, is undeniably on the
  record; the provider cannot disown it.
- ❌ **NOT backdoor detection** — a measurement is an opaque hash. Transparency makes a hidden
  backdoor *undeniable after the fact*, not detectable up front. It bites fully only with
  reproducible builds — a dependency this MVP documents but does not build.

## What is real (runs today)

- **PQ crypto, real (not placeholders) but unaudited** — SLH-DSA (FIPS 205) signed tree heads;
  RFC 6962 inclusion + consistency proofs; X-Wing (X25519 + ML-KEM-768) HNDL-safe session binding.
- **Anti-split-view, two ways** — Web2 witness co-signing (no blockchain), *and* an optional
  on-chain anchor: a real Solana program, built to BPF, deployed to a validator, and exercised
  (`anchor test`: a second root at the same epoch is rejected on-chain).
- **A client verifier compiled to WebAssembly** — verify a receipt in the browser, no server, no
  randomness; it checks the quote signature (against a *mocked* hardware root — see limits), the
  STH signature, Merkle inclusion, and a witness quorum.
- **Reproducible** — `cargo test` (13), `cargo run -p pqtl-cli --bin pqtl-demo` (6 scenarios), and
  a browser demo, all on a stock Rust toolchain; the on-chain piece is verified separately with
  `anchor test` (WSL + a Solana/Anchor toolchain).

## Honest about its limits

A **reference MVP, not production.** The PQ crates (`fips205`, `x-wing`, `ml-kem`) are maintained
and NIST-vector-tested but **independently unaudited**; the hardware attestation quote is **mocked**
(no real TPM root); witness-key distribution and reproducible builds are **assumed**. Every one of
these is stated, with mechanisms and residual risks, in [`THREAT-MODEL.md`](./THREAT-MODEL.md).

---

## A thread, if you want to post it

1/ Confidential inference proves a server is honest — to the *provider's own* keyserver, in
classical crypto. The user verifies nothing. A compromised or compelled provider could serve one
user a backdoored build, signed by its own CI, and nobody outside could tell.

2/ That's a *split-view* attack, and attestation alone can't catch it — the same gap Certificate
Transparency closed for TLS certificate authorities. Nobody had transposed CT to confidential
inference, post-quantum, verified by the end user. So I built a reference for it.

3/ What runs: an append-only log with RFC 6962 inclusion + consistency proofs; SLH-DSA (FIPS 205)
signed tree heads; X-Wing (X25519+ML-KEM-768) HNDL-safe session binding; witness co-signing for
anti-split-view; and a receipt verifier compiled to WebAssembly — you verify in your browser (the
hardware-attestation root is mocked here; see 5/).

4/ Anti-split-view two ways: Web2 witness quorum (no blockchain), and an optional on-chain anchor —
a real Solana program, built, deployed, and exercised on a local validator (a second root at one
epoch is rejected by the chain).

5/ The honest part: this proves **non-equivocation + accountability**, NOT "your build is safe." A
logged hash is opaque; transparency makes a hidden backdoor undeniable *after* it's found, not
detectable up front. Crates are unaudited; the TPM root is mocked. All written down.

6/ Reproducible: `cargo test`, a CLI demo of six attack/defence scenarios, and a browser verifier
on a stock Rust toolchain; the chain piece via `anchor test` (WSL + Solana/Anchor). Repo + threat
model + benchmarks: <link>
