//! RT-2 adversarial tooling: construct malformed `ratchet_oco` RATCHET-branch
//! (selector 3) advance transactions from a single honest baseline, one
//! mutation at a time — the ratchet-advance analog of the plain-fill
//! `--tamper` design (`cli/src/matching.rs::{TamperMode, apply_tamper}`).
//!
//! An attacker who can craft ANY sigscript at the "sibling" input position
//! wants to trick the permissionless RATCHET branch (§4.4 `emit_ratchet` in
//! `ratchet.rs`) into tightening the SL without a genuine qualifying print,
//! into skimming the continuation escrow, or into advancing faster than the
//! rate/travel guards allow. This module is the SINGLE source of truth for
//! both:
//!   - a later live-fire CLI path (constructs the exact malformed tx bytes
//!     that would be submitted to a node), and
//!   - the offline proof (`core/tests/ratchet_tamper_repro.rs`) that runs
//!     those same bytes through the real `kaspa-txscript` `TxScriptEngine`
//!     and asserts rejection.
//!
//! Because both consumers call the identical `RatchetAdvanceScenario` +
//! `RatchetTamperCase::apply` code path, the offline proof is a genuine proof
//! about the tool's own output, not a parallel hand-rolled stand-in.
//!
//! Case catalog (8 categories, cross-referenced to the `core/tests/
//! time_contracts.rs` unit-level ratchet adversarial matrix and
//! `TIME_CONTRACTS_DESIGN.md` §4's guard numbering):
//!   - L1  print below the trigger threshold (R11)
//!   - L2  garbage prints: cancel-shaped / non-covenant / wrong-token
//!         sibling (R7 / R6)
//!   - L3  nested-ratchet print (R7 byte-0 shape guard)
//!   - L4  negative-encoding print: high-bit price bytes read negative,
//!         zero price (R9 positivity)
//!   - L8  self-reference: sii == the ratchet's own input index (R5)
//!   - L10 splice pins: wrong step, no step, SL decrease, mutated
//!         prefix/suffix/cpend byte, shortened new_rs (R13b/c/d)
//!   - L11 continuation escrow skim: short value, forged SPK, unbound
//!         output (R13f)
//!   - RATE rate/travel limiting: sequence < rwin (G1 CSV), or a second
//!         ratchet that would reach TP (G3 R13e travel cap)
//!
//! `honest_baseline()` is a TP 5/1, SL 2/1 (rstep 1, rgap 0, rwin 60,
//! mrv 1_000_000) `ratchet_oco`, ratcheted once by a genuine 3/1 same-token
//! print — byte-for-byte the same numbers as `RatchetScn::happy()` in
//! `core/tests/time_contracts.rs` (the unit-level precedent this tool
//! promotes into reusable, production code). The RATE/travel-cap case is the
//! one exception: demonstrating G3 honestly requires a resting UTXO that has
//! ALREADY been legitimately ratcheted once (SL one step below TP), which is
//! a different starting redeemScript, not a byte tweak of the shared
//! baseline's RS — see `RateLimitVariant::TravelCapExhausted` below. The tx
//! SHAPE (3 inputs: sibling print, ratchet, fee; 4 outputs: print KAS leg,
//! sibling token delivery, ratchet continuation, change) and the assembly
//! code path are identical for every case.

use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};
use kaspa_hashes::Hash;

use crate::contract::spot::order::{
    build_sell_fill_sigscript, build_sell_ioc_fill_sigscript, build_sell_redeem_script,
};
use crate::contract::spot::ratchet::{
    build_ratchet_oco_ratchet_sigscript, build_ratchet_oco_redeem_script,
    derive_ratchet_continuation_rs, RATCHET_PNUM_SL_OFFSET,
};
use crate::contract::spot::receipt::build_sell_cancel_sigscript;
use crate::{blake2b_256, build_p2sh, compute_p2pk_spk_hash, push_data, u64_le};

/// Fixed dev/tooling identity — never CHECKSIG-verified by any scenario this
/// module builds (the wallet fee input is never executed by the offline
/// harness; the CancelShape sibling's forged signature is rejected by R7's
/// byte-0 shape guard before CHECKSIG would run). Deterministic byte
/// patterns, not a real keypair.
const DEV_PUBKEY: [u8; 32] = [0xB4; 32];
const DEV_TOKEN: [u8; 32] = [0x0C; 32];
/// A second, WRONG token id for the L2 wrong-covenant sibling case.
const WRONG_TOKEN: [u8; 32] = [0xD7; 32];

struct DevIdentity {
    pubkey: [u8; 32],
    token: [u8; 32],
    owner_hash: [u8; 32],
    spk_hash: [u8; 32],
    wallet_spk: ScriptPublicKey,
}

fn p2pk_spk(pubkey: &[u8; 32]) -> ScriptPublicKey {
    let mut s = Vec::with_capacity(34);
    s.push(0x20);
    s.extend_from_slice(pubkey);
    s.push(0xac);
    ScriptPublicKey::new(0, s.into())
}

fn dev_identity() -> DevIdentity {
    DevIdentity {
        pubkey: DEV_PUBKEY,
        token: DEV_TOKEN,
        owner_hash: blake2b_256(&DEV_PUBKEY),
        spk_hash: compute_p2pk_spk_hash(&DEV_PUBKEY),
        wallet_spk: p2pk_spk(&DEV_PUBKEY),
    }
}

fn outpoint(b: u8, i: u32) -> TransactionOutpoint {
    TransactionOutpoint::new(Hash::from_bytes([b; 32]), i)
}

/// Sibling "print" sigscript shape riding at input[0] of a ratchet-advance
/// tx — the same-token settle the RATCHET branch reads via
/// `TxInputSigSubstr` to authenticate the trigger price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiblingPrint {
    /// A genuine v18 sell full-fill at (pnum, pden) — canonical shape.
    SellFill { pnum: u64, pden: u64 },
    /// A genuine v18 sell IOC/partial fill (byte 20 = 0x08, fta at [21..29)).
    SellIoc { pnum: u64, pden: u64, fta: u64 },
    /// Hand-rolled canonical-shaped sigscript with raw (unchecked) price
    /// bytes — used to probe the R9 positivity guard.
    RawShape { pnum: [u8; 8], pden: [u8; 8] },
    /// Owner-cancel-shaped sigscript (byte 0 = 0x41) — R7 byte-0 guard.
    CancelShape,
    /// A nested ratchet sigscript (byte 0 = 0x4d pushData opcode) — R7.
    RatchetShape,
}

/// A single ratchet-advance scenario: the honest baseline plus every field
/// an adversarial case can mutate. Mirrors `RatchetScn` in
/// `core/tests/time_contracts.rs`, promoted to a reusable, documented public
/// type so the CLI tool and the offline proof share one code path.
#[derive(Debug, Clone)]
pub struct RatchetAdvanceScenario {
    /// The ratchet_oco UTXO's CURRENT redeemScript (input[1]'s prevout SPK
    /// preimage).
    pub rs: Vec<u8>,
    /// The claimed continuation redeemScript (spliced into output[2]'s SPK
    /// and asserted by R13 against `rs`).
    pub new_rs: Vec<u8>,
    /// The sibling print at input[0].
    pub sibling: SiblingPrint,
    /// Sibling entry: (covenant id present, correct token) — R6.
    pub sibling_cov: (bool, bool),
    /// Sibling's token amount (its UTXO value == vol for a full-fill print).
    pub sibling_tokens: u64,
    /// Output[0] value: the print's KAS leg (koi = 0 in the sibling
    /// sigscript) — R12 settle-magnitude re-check.
    pub print_kas: u64,
    /// The ratchet_oco UTXO's escrow value (input[1]'s prevout amount).
    pub escrow: u64,
    /// Output[2] value: the claimed continuation escrow — R13f.
    pub continuation_value: u64,
    /// Whether output[2] carries `CovenantBinding(1, token)` (auth[0] of the
    /// ratchet input) — R13f.
    pub continuation_bound: bool,
    /// If true, output[2]'s SPK is `P2SH(rs)` (the OLD address) instead of
    /// `P2SH(new_rs)` — R13f forged-SPK probe.
    pub forge_continuation_spk: bool,
    /// The ratchet input's nSequence — G1 (R4 CSV) rate limit.
    pub sequence: u64,
    /// `sii`: the sibling input index the ratchet sigscript names — R5/R6/R7.
    pub sii: u16,
    /// Tx lock_time (R3 expiry gate; 0 in every scenario here).
    pub lock_time: u64,
}

impl RatchetAdvanceScenario {
    /// TP 5/1, SL 2/1, rstep 1, rgap 0, rwin 60, mrv 1_000_000 — advanced one
    /// step by a genuine 3/1 same-token print. Every guard is satisfied;
    /// `build_tx()` on this scenario MUST pass the real script engine on
    /// both input[0] (the sibling's own covenant) and input[1] (the
    /// ratchet).
    pub fn honest_baseline() -> Self {
        let id = dev_identity();
        let rs = build_ratchet_oco_redeem_script(
            1, 0, 60, 1_000_000, 5, 1, 1, 2, 1, 1, &id.owner_hash, &id.spk_hash, &id.spk_hash,
            30, 0, 0,
        )
        .expect("honest baseline RS must build");
        let new_rs =
            derive_ratchet_continuation_rs(&rs).expect("honest baseline splice must derive");
        RatchetAdvanceScenario {
            rs,
            new_rs,
            sibling: SiblingPrint::SellFill { pnum: 3, pden: 1 },
            sibling_cov: (true, true),
            sibling_tokens: 10_000_000,
            print_kas: 30_000_000,
            escrow: 5_000_000,
            continuation_value: 5_000_000,
            continuation_bound: true,
            forge_continuation_spk: false,
            sequence: 60,
            sii: 0,
            lock_time: 0,
        }
    }

    /// Assemble the on-chain tx + UTXO entries for this scenario. Input
    /// layout: [0] sibling print, [1] ratchet_oco (RATCHET branch, selector
    /// 3), [2] wallet fee (never executed). Output layout: [0] print's KAS
    /// leg, [1] sibling token delivery, [2] ratchet continuation, [3]
    /// change. This is the ONLY tx-assembly code path — every tamper case
    /// differs from `honest_baseline()` only in the `RatchetAdvanceScenario`
    /// fields fed into it.
    pub fn build_tx(&self) -> (Transaction, Vec<UtxoEntry>) {
        let id = dev_identity();
        let token_hash = Hash::from_bytes(id.token);
        let wrong_token_hash = Hash::from_bytes(WRONG_TOKEN);

        let sib_sell_rs = build_sell_redeem_script(
            3, 1, 1, &id.owner_hash, &id.spk_hash, &id.spk_hash, 30, 0, 0,
        )
        .expect("sibling sell RS must build");

        let sib_ss = match &self.sibling {
            SiblingPrint::SellFill { pnum, pden } => {
                build_sell_fill_sigscript(0, *pnum, *pden, &sib_sell_rs)
            }
            SiblingPrint::SellIoc { pnum, pden, fta } => {
                build_sell_ioc_fill_sigscript(0, *pnum, *pden, *fta, &sib_sell_rs)
            }
            SiblingPrint::RawShape { pnum, pden } => {
                let mut ss = vec![0x01, 0x00, 0x08];
                ss.extend_from_slice(pnum);
                ss.push(0x08);
                ss.extend_from_slice(pden);
                ss.push(0x51); // full-fill selector shape
                ss.extend_from_slice(&push_data(&sib_sell_rs));
                ss
            }
            SiblingPrint::CancelShape => {
                build_sell_cancel_sigscript(&[0x11; 64], &id.pubkey, &sib_sell_rs)
            }
            SiblingPrint::RatchetShape => {
                build_ratchet_oco_ratchet_sigscript(&self.new_rs, &self.rs, 1, &self.rs)
            }
        };

        let ratchet_ss =
            build_ratchet_oco_ratchet_sigscript(&self.new_rs, &self.rs, self.sii, &self.rs);

        let inputs = vec![
            TransactionInput::new(outpoint(0x10, 0), sib_ss, 50, 0),
            TransactionInput::new(outpoint(0x20, 0), ratchet_ss, self.sequence, 0),
            TransactionInput::new(outpoint(0x30, 0), vec![0x41; 66], 0, 1),
        ];

        let cont_spk =
            if self.forge_continuation_spk { build_p2sh(&self.rs) } else { build_p2sh(&self.new_rs) };

        let outputs = vec![
            // [0] the print's KAS leg (koi = 0).
            TransactionOutput::with_covenant(self.print_kas, id.wallet_spk.clone(), None),
            // [1] sibling token delivery (auth[0] of the sibling when bound).
            TransactionOutput::with_covenant(
                self.sibling_tokens,
                id.wallet_spk.clone(),
                match self.sibling_cov {
                    (true, true) => Some(CovenantBinding::new(0, token_hash)),
                    (true, false) => Some(CovenantBinding::new(0, wrong_token_hash)),
                    (false, _) => None,
                },
            ),
            // [2] the ratchet continuation (auth[0] of the ratchet input
            // when bound).
            TransactionOutput::with_covenant(
                self.continuation_value,
                cont_spk,
                if self.continuation_bound {
                    Some(CovenantBinding::new(1, token_hash))
                } else {
                    None
                },
            ),
            TransactionOutput::with_covenant(500_000_000, id.wallet_spk.clone(), None),
        ];

        let entries = vec![
            UtxoEntry {
                amount: self.sibling_tokens,
                script_public_key: build_p2sh(&sib_sell_rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: match self.sibling_cov {
                    (true, true) => Some(token_hash),
                    (true, false) => Some(wrong_token_hash),
                    (false, _) => None,
                },
            },
            UtxoEntry {
                amount: self.escrow,
                script_public_key: build_p2sh(&self.rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(token_hash),
            },
            UtxoEntry {
                amount: 1_000_000_000,
                script_public_key: id.wallet_spk,
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: None,
            },
        ];

        let tx = Transaction::new(1, inputs, outputs, self.lock_time, Default::default(), 0, vec![]);
        (tx, entries)
    }
}

/// L2 sub-cases: garbage prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2Variant {
    /// Owner-cancel-shaped sibling (byte 0 = 0x41) — R7.
    CancelShapeSibling,
    /// Sibling UTXO carries no covenant id at all — R6 (ZERO_HASH != own id).
    NonCovenantSibling,
    /// Sibling UTXO carries a DIFFERENT token's covenant id — R6.
    WrongTokenSibling,
}

/// L4 sub-cases: negative-encoding prints (R9 positivity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Variant {
    /// pden_att's high bit set — reads negative as i64.
    NegPden,
    /// pnum_att's high bit set — reads negative as i64.
    NegPnum,
    /// pden_att == 0 (floored positivity, not just sign).
    ZeroPden,
}

/// L10 sub-cases: splice pins (R13b/R13c/R13d).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L10Variant {
    /// new_rs advances pnum_sl by 2*rstep instead of rstep.
    WrongStep,
    /// new_rs == old rs (no step at all).
    NoStep,
    /// new_rs DECREASES pnum_sl — one-way monotonicity.
    SlDecrease,
    /// A prefix byte (outside the pnum_sl window) is flipped.
    MutatedPrefix,
    /// The expiry byte (suffix, RS[200]) is flipped — a ratchet can never
    /// extend the order's life.
    MutatedSuffixExpiry,
    /// The cpend byte (RS[198]) is flipped.
    MutatedCpend,
    /// new_rs is one byte shorter than it should be.
    Shortened,
}

/// L11 sub-cases: continuation escrow skim (R13f).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L11Variant {
    /// Continuation output value is 1 sompi short of full escrow.
    ShortValue,
    /// Continuation output SPK is `P2SH(rs)` (the OLD address).
    ForgedSpk,
    /// Continuation output carries no covenant binding at all.
    Unbound,
}

/// RATE sub-cases: G1 (rwin CSV) and G3 (travel cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitVariant {
    /// nSequence one below rwin — the CSV gate has not elapsed.
    RwinTooSoon,
    /// A second ratchet step that would land the SL exactly on TP.
    TravelCapExhausted,
}

/// The 8-case RT-2 adversarial catalog. Every variant corresponds to one
/// guard family in `TIME_CONTRACTS_DESIGN.md` §4.4/§4.5 and to the unit-level
/// case of the same name in `core/tests/time_contracts.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetTamperCase {
    L1PrintBelowThreshold,
    L2GarbagePrint(L2Variant),
    L3NestedRatchetPrint,
    L4NegativeEncoding(L4Variant),
    L8SelfReference,
    L10SplicePin(L10Variant),
    L11EscrowSkim(L11Variant),
    RateLimit(RateLimitVariant),
}

impl RatchetTamperCase {
    /// Every concrete tamper selector (21 — the 8 categories' sub-variants).
    pub fn all() -> Vec<RatchetTamperCase> {
        use L2Variant::*;
        use L4Variant::*;
        use L10Variant::*;
        use L11Variant::*;
        use RateLimitVariant::*;
        use RatchetTamperCase::*;
        vec![
            L1PrintBelowThreshold,
            L2GarbagePrint(CancelShapeSibling),
            L2GarbagePrint(NonCovenantSibling),
            L2GarbagePrint(WrongTokenSibling),
            L3NestedRatchetPrint,
            L4NegativeEncoding(NegPden),
            L4NegativeEncoding(NegPnum),
            L4NegativeEncoding(ZeroPden),
            L8SelfReference,
            L10SplicePin(WrongStep),
            L10SplicePin(NoStep),
            L10SplicePin(SlDecrease),
            L10SplicePin(MutatedPrefix),
            L10SplicePin(MutatedSuffixExpiry),
            L10SplicePin(MutatedCpend),
            L10SplicePin(Shortened),
            L11EscrowSkim(ShortValue),
            L11EscrowSkim(ForgedSpk),
            L11EscrowSkim(Unbound),
            RateLimit(RwinTooSoon),
            RateLimit(TravelCapExhausted),
        ]
    }

    /// The CLI-facing selector string (`--tamper` value / `parse` input).
    pub fn id(&self) -> &'static str {
        use L2Variant::*;
        use L4Variant::*;
        use L10Variant::*;
        use L11Variant::*;
        use RateLimitVariant::*;
        use RatchetTamperCase::*;
        match self {
            L1PrintBelowThreshold => "l1",
            L2GarbagePrint(CancelShapeSibling) => "l2-cancel-shape",
            L2GarbagePrint(NonCovenantSibling) => "l2-noncovenant",
            L2GarbagePrint(WrongTokenSibling) => "l2-wrong-token",
            L3NestedRatchetPrint => "l3",
            L4NegativeEncoding(NegPden) => "l4-neg-pden",
            L4NegativeEncoding(NegPnum) => "l4-neg-pnum",
            L4NegativeEncoding(ZeroPden) => "l4-zero-pden",
            L8SelfReference => "l8",
            L10SplicePin(WrongStep) => "l10-wrong-step",
            L10SplicePin(NoStep) => "l10-no-step",
            L10SplicePin(SlDecrease) => "l10-sl-decrease",
            L10SplicePin(MutatedPrefix) => "l10-mutated-prefix",
            L10SplicePin(MutatedSuffixExpiry) => "l10-mutated-expiry",
            L10SplicePin(MutatedCpend) => "l10-mutated-cpend",
            L10SplicePin(Shortened) => "l10-shortened",
            L11EscrowSkim(ShortValue) => "l11-short-value",
            L11EscrowSkim(ForgedSpk) => "l11-forged-spk",
            L11EscrowSkim(Unbound) => "l11-unbound",
            RateLimit(RwinTooSoon) => "rate-rwin",
            RateLimit(TravelCapExhausted) => "rate-travel-cap",
        }
    }

    /// The 8-category catalog id (matches the RT-2 case catalog exactly).
    pub fn category(&self) -> &'static str {
        match self {
            RatchetTamperCase::L1PrintBelowThreshold => "L1",
            RatchetTamperCase::L2GarbagePrint(_) => "L2",
            RatchetTamperCase::L3NestedRatchetPrint => "L3",
            RatchetTamperCase::L4NegativeEncoding(_) => "L4",
            RatchetTamperCase::L8SelfReference => "L8",
            RatchetTamperCase::L10SplicePin(_) => "L10",
            RatchetTamperCase::L11EscrowSkim(_) => "L11",
            RatchetTamperCase::RateLimit(_) => "RATE",
        }
    }

    /// The guard(s) the real script engine is expected to enforce.
    pub fn expected_guard(&self) -> &'static str {
        use L2Variant::*;
        use L4Variant::*;
        use L10Variant::*;
        use L11Variant::*;
        use RateLimitVariant::*;
        use RatchetTamperCase::*;
        match self {
            L1PrintBelowThreshold => "R11 (cross-multiplied trigger)",
            L2GarbagePrint(CancelShapeSibling) => "R7 (canonical-shape byte 0)",
            L2GarbagePrint(NonCovenantSibling) => "R6 (OpInputCovenantId == ZERO_HASH)",
            L2GarbagePrint(WrongTokenSibling) => "R6 (covenant id mismatch)",
            L3NestedRatchetPrint => "R7 (canonical-shape byte 0, ratchet pushData is 0x4d)",
            L4NegativeEncoding(NegPden) => "R9 (pden_att >= 1)",
            L4NegativeEncoding(NegPnum) => "R9 (pnum_att >= 1)",
            L4NegativeEncoding(ZeroPden) => "R9 (pden_att >= 1, floor)",
            L8SelfReference => "R5 (sii != self)",
            L10SplicePin(WrongStep) => "R13d (new == old + rstep, exact)",
            L10SplicePin(NoStep) => "R13d (new == old + rstep, exact)",
            L10SplicePin(SlDecrease) => "R13d (one-way monotonicity)",
            L10SplicePin(MutatedPrefix) => "R13b (prefix [0..100) byte-equal)",
            L10SplicePin(MutatedSuffixExpiry) => "R13c (suffix [108..size) byte-equal)",
            L10SplicePin(MutatedCpend) => "R13c (suffix [108..size) byte-equal)",
            L10SplicePin(Shortened) => "R13c (EQUAL pins new_rs length)",
            L11EscrowSkim(ShortValue) => "R13f (continuation amount >= full escrow)",
            L11EscrowSkim(ForgedSpk) => "R13f (continuation SPK == P2SH(new_rs))",
            L11EscrowSkim(Unbound) => "R13f / Fix-3 (auth[0] must carry the binding)",
            RateLimit(RwinTooSoon) => "G1 / R4 (rwin CSV)",
            RateLimit(TravelCapExhausted) => "G3 / R13e (SL may never reach TP)",
        }
    }

    /// Parse a CLI selector string (see `id()` for the exact set).
    pub fn parse(s: &str) -> Option<RatchetTamperCase> {
        Self::all().into_iter().find(|c| c.id() == s)
    }

    /// Apply this case's mutation to an otherwise-honest scenario. Callers
    /// should start from `RatchetAdvanceScenario::honest_baseline()` (or, for
    /// `RateLimit(TravelCapExhausted)`, accept that this case replaces the
    /// baseline's `rs`/`new_rs`/`sibling`/`print_kas` outright — see the
    /// module doc comment).
    pub fn apply(&self, scn: &mut RatchetAdvanceScenario) {
        use L2Variant::*;
        use L4Variant::*;
        use L10Variant::*;
        use L11Variant::*;
        use RateLimitVariant::*;
        use RatchetTamperCase::*;
        match self {
            L1PrintBelowThreshold => {
                // Threshold = pnum_sl + rstep + rgap = 2+1+0 = 3/1; 2/1 fails.
                scn.sibling = SiblingPrint::SellFill { pnum: 2, pden: 1 };
                scn.print_kas = 20_000_000;
            }
            L2GarbagePrint(CancelShapeSibling) => {
                scn.sibling = SiblingPrint::CancelShape;
            }
            L2GarbagePrint(NonCovenantSibling) => {
                scn.sibling_cov = (false, true);
            }
            L2GarbagePrint(WrongTokenSibling) => {
                scn.sibling_cov = (true, false);
            }
            L3NestedRatchetPrint => {
                scn.sibling = SiblingPrint::RatchetShape;
            }
            L4NegativeEncoding(NegPden) => {
                scn.sibling =
                    SiblingPrint::RawShape { pnum: u64_le(3), pden: [0, 0, 0, 0, 0, 0, 0, 0x80] };
            }
            L4NegativeEncoding(NegPnum) => {
                scn.sibling =
                    SiblingPrint::RawShape { pnum: [0, 0, 0, 0, 0, 0, 0, 0x80], pden: u64_le(1) };
            }
            L4NegativeEncoding(ZeroPden) => {
                scn.sibling = SiblingPrint::RawShape { pnum: u64_le(3), pden: u64_le(0) };
            }
            L8SelfReference => {
                scn.sii = 1; // the ratchet input's own index
            }
            L10SplicePin(WrongStep) => {
                let step1 = derive_ratchet_continuation_rs(&scn.rs).expect("step 1 splice");
                scn.new_rs = derive_ratchet_continuation_rs(&step1).expect("step 2 splice");
            }
            L10SplicePin(NoStep) => {
                scn.new_rs = scn.rs.clone();
            }
            L10SplicePin(SlDecrease) => {
                let mut down = scn.rs.clone();
                down[RATCHET_PNUM_SL_OFFSET..RATCHET_PNUM_SL_OFFSET + 8]
                    .copy_from_slice(&u64_le(1));
                scn.new_rs = down;
            }
            L10SplicePin(MutatedPrefix) => {
                let mut m = derive_ratchet_continuation_rs(&scn.rs).expect("splice");
                m[10] ^= 1; // rgap value byte, inside the prefix window
                scn.new_rs = m;
            }
            L10SplicePin(MutatedSuffixExpiry) => {
                let mut m = derive_ratchet_continuation_rs(&scn.rs).expect("splice");
                m[200] ^= 1; // expiry value byte, inside the suffix window
                scn.new_rs = m;
            }
            L10SplicePin(MutatedCpend) => {
                let mut m = derive_ratchet_continuation_rs(&scn.rs).expect("splice");
                m[198] = 0x51; // cpend byte
                scn.new_rs = m;
            }
            L10SplicePin(Shortened) => {
                let mut m = derive_ratchet_continuation_rs(&scn.rs).expect("splice");
                m.pop();
                scn.new_rs = m;
            }
            L11EscrowSkim(ShortValue) => {
                scn.continuation_value = scn.escrow.saturating_sub(1);
            }
            L11EscrowSkim(ForgedSpk) => {
                scn.forge_continuation_spk = true;
            }
            L11EscrowSkim(Unbound) => {
                scn.continuation_bound = false;
            }
            RateLimit(RwinTooSoon) => {
                scn.sequence = scn.sequence.saturating_sub(1);
            }
            RateLimit(TravelCapExhausted) => {
                // Demonstrating G3 honestly needs a resting UTXO ALREADY one
                // legitimate ratchet away from TP: TP=4/1, SL=2/1, rstep=1 —
                // step 1 (SL 2->3) is legal; this scenario OFFERS a second,
                // cap-violating step (3->4==TP). Same tx shape, different
                // (still fully self-consistent) starting RS — see module doc.
                let id = dev_identity();
                let rs0 = build_ratchet_oco_redeem_script(
                    1, 0, 60, 1_000_000, 4, 1, 1, 2, 1, 1, &id.owner_hash, &id.spk_hash,
                    &id.spk_hash, 30, 0, 0,
                )
                .expect("travel-cap precursor RS");
                let rs1 = derive_ratchet_continuation_rs(&rs0).expect("legal step 1 splice");
                scn.rs = rs1.clone();
                scn.new_rs =
                    derive_ratchet_continuation_rs(&rs1).expect("illegal step 2 splice");
                scn.sibling = SiblingPrint::SellFill { pnum: 5, pden: 1 };
                scn.print_kas = 5 * scn.sibling_tokens;
            }
        }
    }

    /// Build a `RatchetAdvanceScenario` for this case, starting from
    /// `RatchetAdvanceScenario::honest_baseline()` and applying this case's
    /// mutation — the single call sites (CLI + offline proof) should use.
    pub fn scenario(&self) -> RatchetAdvanceScenario {
        let mut scn = RatchetAdvanceScenario::honest_baseline();
        self.apply(&mut scn);
        scn
    }
}
