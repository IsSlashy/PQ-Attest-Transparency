# CHAIN-ANCHOR.md — the optional on-chain anchoring backend

This is the `ChainAnchor` backend of ADR-004: instead of (or alongside) a witness federation,
publish each Signed-Tree-Head root on a **public, append-only ledger**. Equivocation then becomes
*impossible at the medium*, because the ledger refuses a second, different root at an epoch it has
already written — so the client needs **no witness federation** to detect a split-view.

> This is a **bootstrap-cost** argument, not a performance one. A chain write is *slower* than a
> Web2 witness cosignature; what it removes is the cost of recruiting, operating, and pinning an
> independent witness set. Never sell it as "faster" (see ADR-004).

## Two implementations of one interface

`pqtl_core::chain::Ledger` is the seam:

- `submit(epoch, root) -> bool` — commit a root; returns `false` if a *different* root is already
  committed at that epoch (idempotent if equal).
- `read(epoch) -> Option<root>` — read the committed root.

1. **`MockLedger`** (in-process). Models the one property that matters — append-only + immutable
   per epoch. Used by `ChainAnchor<MockLedger>` in the CLI demo (scenario 6) and unit test
   `chain_anchor_immutable_ledger_blocks_equivocation`. This is what *runs in the test suite*.
2. **`sth-anchor`** — a real Solana program (`onchain/programs/sth-anchor`) that enforces the same
   property on-chain. This is the production path.

## The Solana program

```
account SthAnchor  { log_id, epoch, root, timestamp, bump }   PDA: [b"sth", log_authority, epoch]
account WitnessSet { log_id, commitment, timestamp, bump }    PDA: [b"witnessset", log_authority]
anchor_root(epoch, root)        — init-once per (log, epoch): immutable STH-root anchor
anchor_witness_set(commitment)  — init-once per log: immutable witness-set commitment (M8), so a
                                  client authenticates the witness keys from the chain, not the provider
```

Immutability comes for free from Anchor's `init`: a PDA can be **created exactly once**, so a
second `anchor_root` at the same `(log_authority, epoch)` aborts ("account already in use"). That
is exactly `MockLedger::submit` rejecting a conflicting root.

**Client read path — no on-chain verifier needed.** The client derives the PDA from
`(log_authority, epoch)` and does a plain `getAccountInfo`, then byte-compares the stored `root`
to the STH root in its receipt. (Per the M5 extraction audit, the Protocol-01 STARK verifier is
*not* needed here — anchoring a 32-byte root is a bare account write + read.)

## Verified status (honest)

Built, deployed, AND exercised end-to-end **in WSL** (Ubuntu) — Windows-native `cargo build-sbf`
is blocked by a platform-tools symlink-extraction bug (`os error 183`), a host limitation, not a
code one.

- **Builds to deployable bytecode.** `onchain/build-in-wsl.sh` → `cargo build-sbf` produces
  `target/deploy/sth_anchor.so` (194,224 bytes), platform-tools v1.52 / solana 3.1.9. Host
  `cargo check` also type-checks the source.
- **Deploys to a live validator.** `onchain/deploy-in-wsl.sh` starts `solana-test-validator`,
  deploys the `.so`, and `solana program show` confirms it on-chain (owner `BPFLoaderUpgradeable`).
- **Behaviour exercised on-chain.** `onchain/test-in-wsl.sh` runs `anchor test` (build → validator
  → deploy → a TS client, `tests/sth-anchor.ts`): it publishes a root at epoch 7 and reads it
  back; submits a SECOND, different root at epoch 7 and asserts it is **rejected** (the PDA is
  init-once); then publishes at epoch 8. A second test anchors a **witness-set commitment** and
  asserts a second, different commitment is rejected (M8). Result: **`2 passing`**. These are the
  same properties the in-process `MockLedger` / `new_checked` tests prove, now demonstrated against
  a real deployed program.

Reproduce:

```bash
wsl bash /mnt/<drive>/<path>/onchain/build-in-wsl.sh   # just build the .so
wsl bash /mnt/<drive>/<path>/onchain/test-in-wsl.sh    # full: build + validator + deploy + exercise
```

**Honest notes.** `anchor keys sync` set `declare_id!` (and `Anchor.toml`) to the program
keypair's id (`3uX7o96x…`); that keypair lives under `onchain/target` (gitignored), so a fresh
clone regenerates its own id with `anchor keys sync`. Node 18 needs `yarn install
--ignore-engines` (a transitive dep declares node ≥ 20). The exercise depends on a running local
validator; nothing about it is mocked.

## Residual risks (for a real deployment)

- **Anchoring signer**: key custody, rent funding, retries, RPC liveness — the real operational
  work, not the ~80-line program.
- **What "anchored" means**: finality / reorg depth / monitoring cadence must be defined; a client
  should require the anchor account to be finalized before trusting it.
- **Epoch mapping**: here `epoch = tree_size`; a real deployment may prefer a monotonic counter or
  a time-bucketed epoch, and should bound the publish cadence (a CT-style maximum-merge-delay).
