# BENCHMARKS.md — "how much does post-quantum cost?"

Two axes: **size** (bytes on the wire / in a receipt) and **time** (latency per operation).
Reproduce with:

```bash
cargo run --release -p pqtl-cli --bin pqtl-bench
```

> **Read these as indicative single-machine numbers, not a controlled study.** Latencies were
> taken on one developer machine (Windows, `--release`, rustc 1.95) with `std::time::Instant`,
> median over N iterations, no CPU-governor pinning — thermal throttling and frequency scaling
> are uncontrolled. They are meant to show *orders of magnitude* and *ratios between
> operations*, which are stable; absolute values are not portable. Sizes, by contrast, are
> exact constants.

---

## Part A — the PQ size tax (exact)

| Object the client handles | Classical | This project (PQ) | Factor |
|---|--:|--:|--:|
| STH signature | Ed25519 **64 B** | SLH-DSA-128s **7856 B** | **≈123×** |
| Signer public key | Ed25519 **32 B** | SLH-DSA-128s **32 B** | **1× (no tax)** |
| Session public key | X25519 **32 B** | X-Wing **1216 B** | ≈38× |
| Session ciphertext | X25519 **32 B** (ephemeral) | X-Wing **1120 B** (ML-KEM-768 = 1088 B) | ≈35× |
| Session shared secret | X25519 **32 B** | X-Wing **32 B** | **1× (no tax)** |
| **Full session receipt** | — | **10 344 B** | dominated by the 7856 B signature |

Alternative signature framings: ECDSA P-256 ≈ 64 B raw / 70–72 B DER (≈109–123×); RSA-2048
256 B (≈31×, but with a far larger key/cert than Ed25519's 32 B).

**Takeaway:** the tax is concentrated in the **signature** (~123× vs Ed25519) and the
**KEM handshake** (~35–38×). The values the client *compares* — the signer public key and the
shared secret — are **unchanged at 32 B**. A receipt is ~10 KB, almost all of it the STH
signature.

Sources: Ed25519 32 B keys / 64 B sigs (RFC 8032; hacl-star.github.io/HaclSig.html). ECDSA
P-256 raw 64 B, DER 70–72 B (ANSI X9.62 / RFC 3279). RSA-2048 256 B (RFC 8017 PKCS#1 v2.2).
X25519 32 B pubkey/shared (RFC 7748). ML-KEM-768 ct 1088 B (FIPS 203). X-Wing constants
1216 B / 1120 B (draft-connolly-cfrg-xwing-kem; `x-wing` crate).

---

## Part B — the PQ time cost (indicative, single machine)

Grouped by who pays it. **Median latency.**

**Log operator — one-time or per-STH (off the client's critical path):**

| Operation | median | notes |
|---|--:|---|
| SLH-DSA-128s keygen | ~17 ms | once per operator/witness key |
| **SLH-DSA-128s sign (STH)** | **~130 ms** | the single expensive op; the `128s` set trades slow signing for small-ish sigs. Per STH, not per request. |
| Merkle inclusion-proof gen (n=1024) | ~0.08 ms | O(n) — the log is non-incremental (rebuilds the tree per query) |
| Merkle inclusion-proof gen (n=65536) | ~4.7 ms | O(n); an incremental O(log n) log is the documented next optimization |

**Client — per session, the hot path (this is what user experience feels):**

| Operation | median | notes |
|---|--:|---|
| **Full receipt verify** | **~0.14 ms** | binding hash + 1 SLH-DSA verify + inclusion verify + anchor lookup |
| SLH-DSA-128s verify | ~0.13 ms | dominates the receipt verify |
| Merkle inclusion verify | ~0.001 ms | O(log n) |
| Consistency verify | <0.001 ms | O(log n) |
| X-Wing keygen | ~0.05 ms | |
| X-Wing decapsulate | ~0.11 ms | RNG-free |

**Keyserver:** X-Wing encapsulate ~0.08 ms. **Witness:** cosign ≈ one SLH-DSA sign (~130 ms);
`WitnessAnchor.ingest` of one cosignature ≈ one SLH-DSA verify (~0.13 ms), so a quorum of *k*
costs ≈ *k* × 0.13 ms.

**Takeaway:** the expensive operation, SLH-DSA **signing (~130 ms)**, is paid **once per STH by
the operator/witnesses**, never by the client per request. Everything on the **client path is
sub-millisecond** (~0.14 ms to verify a receipt end to end). So the honest message is:

> **Post-quantum safety here costs bytes (a ~10 KB receipt) and operator sign-time (~130 ms per
> STH) — not client-side verification latency, which stays sub-millisecond.**

The one efficiency caveat the bench makes visible: inclusion/consistency **proof generation is
O(n)** (4.7 ms at 65 k entries) because the M0 log rebuilds the Merkle tree per query;
*verification* is already O(log n). Porting Protocol-01's incremental `filled_subtrees` log
(documented in `docs/EXTRACTION.md`) makes generation O(log n) too — a deferred optimization,
not a soundness issue.

---

*These numbers measure the primitives as wired in `pqtl-core`; they do not measure (and make no
claim about) the security of the unaudited crates involved. See `THREAT-MODEL.md`.*
