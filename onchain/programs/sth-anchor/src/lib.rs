//! sth-anchor — the real on-chain backend for `pqtl_core::chain::ChainAnchor`.
//!
//! A transparency-log operator publishes each Signed-Tree-Head root at an epoch. The entry
//! lives in a PDA seeded by `(log_authority, epoch)`, created with `init` — so it can be
//! created EXACTLY ONCE. A second `anchor_root` at the same epoch fails ("account already in
//! use"), which makes the ledger append-only and IMMUTABLE per epoch: the chain itself rejects
//! an equivocating second root. A client verifies an STH by deriving the PDA and reading `root`
//! (a plain account read — no on-chain verifier needed).
//!
//! This mirrors `pqtl_core::chain::Ledger` exactly: `submit` ≈ `anchor_root` (init-once),
//! `read` ≈ deriving + reading the PDA. See `docs/CHAIN-ANCHOR.md`.

use anchor_lang::prelude::*;

declare_id!("3uX7o96xaZrjAXpNEEQCkxdHRQqBFRgpR3jUd5gUDjUC");

#[program]
pub mod sth_anchor {
    use super::*;

    /// Publish an STH `root` at `epoch`. The PDA is created with `init`, so an epoch can be
    /// written at most once; a second call at the same `(log_authority, epoch)` aborts, making
    /// equivocation (two different roots at one epoch) impossible on-chain.
    pub fn anchor_root(ctx: Context<AnchorRoot>, epoch: u64, root: [u8; 32]) -> Result<()> {
        let entry = &mut ctx.accounts.entry;
        entry.log_id = ctx.accounts.log_authority.key();
        entry.epoch = epoch;
        entry.root = root;
        entry.timestamp = Clock::get()?.unix_timestamp;
        entry.bump = ctx.bumps.entry;
        emit!(RootAnchored {
            log_id: entry.log_id,
            epoch,
            root,
            timestamp: entry.timestamp,
        });
        Ok(())
    }

    /// Publish the log's canonical witness-set commitment. The PDA is per `log_authority` and
    /// created with `init`, so the witness set is immutable: a second, different commitment is
    /// rejected. A client reads this to authenticate the witness keys from the chain instead of
    /// from the (untrusted) provider — closing the witness-distribution gap.
    pub fn anchor_witness_set(ctx: Context<AnchorWitnessSet>, commitment: [u8; 32]) -> Result<()> {
        let ws = &mut ctx.accounts.witness_set;
        ws.log_id = ctx.accounts.log_authority.key();
        ws.commitment = commitment;
        ws.timestamp = Clock::get()?.unix_timestamp;
        ws.bump = ctx.bumps.witness_set;
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(epoch: u64, root: [u8; 32])]
pub struct AnchorRoot<'info> {
    /// One entry per `(log_authority, epoch)`. `init` => creatable exactly once (immutability).
    #[account(
        init,
        payer = log_authority,
        space = 8 + SthAnchor::SIZE,
        seeds = [b"sth", log_authority.key().as_ref(), &epoch.to_le_bytes()],
        bump
    )]
    pub entry: Account<'info, SthAnchor>,
    #[account(mut)]
    pub log_authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct SthAnchor {
    /// The transparency log's authority (its on-chain identity).
    pub log_id: Pubkey,
    /// Monotonic epoch (e.g. the tree size at which this root was published).
    pub epoch: u64,
    /// The committed Merkle root / Signed-Tree-Head root.
    pub root: [u8; 32],
    /// On-chain wall-clock at publication (a freshness signal for clients).
    pub timestamp: i64,
    pub bump: u8,
}

impl SthAnchor {
    pub const SIZE: usize = 32 + 8 + 32 + 8 + 1;
}

#[derive(Accounts)]
pub struct AnchorWitnessSet<'info> {
    /// One witness-set commitment per `log_authority`. `init` => creatable exactly once.
    #[account(
        init,
        payer = log_authority,
        space = 8 + WitnessSet::SIZE,
        seeds = [b"witnessset", log_authority.key().as_ref()],
        bump
    )]
    pub witness_set: Account<'info, WitnessSet>,
    #[account(mut)]
    pub log_authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct WitnessSet {
    pub log_id: Pubkey,
    /// Canonical commitment to the authoritative witness set (id + pubkey, domain-separated).
    pub commitment: [u8; 32],
    pub timestamp: i64,
    pub bump: u8,
}

impl WitnessSet {
    pub const SIZE: usize = 32 + 32 + 8 + 1;
}

#[event]
pub struct RootAnchored {
    pub log_id: Pubkey,
    pub epoch: u64,
    pub root: [u8; 32],
    pub timestamp: i64,
}
