import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SthAnchor } from "../target/types/sth_anchor";
import { assert } from "chai";

describe("sth-anchor: append-only, immutable-per-epoch STH anchoring", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.SthAnchor as Program<SthAnchor>;
  const authority = provider.wallet.publicKey;

  const pda = (epoch: anchor.BN) =>
    anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("sth"), authority.toBuffer(), epoch.toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];

  const submit = (epoch: anchor.BN, root: number[]) =>
    program.methods
      .anchorRoot(epoch, root)
      .accountsPartial({
        entry: pda(epoch),
        logAuthority: authority,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

  it("anchors a root, then REJECTS a different root at the same epoch", async () => {
    const epoch = new anchor.BN(7);
    const root = Array(32).fill(1);

    // 1. publish the honest root
    await submit(epoch, root);
    const acct = await program.account.sthAnchor.fetch(pda(epoch));
    assert.deepEqual(acct.root, root, "stored root must match what was published");
    assert.equal(acct.epoch.toNumber(), 7);
    assert.equal(acct.logId.toBase58(), authority.toBase58());

    // 2. an equivocating second root at the SAME epoch must fail (the PDA is init-once)
    let rejected = false;
    try {
      await submit(epoch, Array(32).fill(2));
    } catch (_e) {
      rejected = true;
    }
    assert.isTrue(rejected, "a second, different root at the same epoch must be rejected on-chain");

    // 3. a new epoch is fine (append-only, not write-once-globally)
    const epoch2 = new anchor.BN(8);
    await submit(epoch2, Array(32).fill(3));
    const acct2 = await program.account.sthAnchor.fetch(pda(epoch2));
    assert.equal(acct2.epoch.toNumber(), 8);

    console.log("    on-chain: root anchored, equivocation rejected, next epoch accepted ✓");
  });

  it("anchors a witness-set commitment immutably", async () => {
    const ws = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("witnessset"), authority.toBuffer()],
      program.programId
    )[0];
    const commit = Array(32).fill(7);

    await program.methods
      .anchorWitnessSet(commit)
      .accountsPartial({
        witnessSet: ws,
        logAuthority: authority,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();
    const acct = await program.account.witnessSet.fetch(ws);
    assert.deepEqual(acct.commitment, commit, "stored witness-set commitment must match");

    // a second, DIFFERENT commitment at the same PDA must be rejected (init-once)
    let rejected = false;
    try {
      await program.methods
        .anchorWitnessSet(Array(32).fill(8))
        .accountsPartial({
          witnessSet: ws,
          logAuthority: authority,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
    } catch (_e) {
      rejected = true;
    }
    assert.isTrue(rejected, "a second, different witness-set commitment must be rejected");
    console.log("    on-chain: witness-set commitment anchored, second one rejected ✓");
  });
});
