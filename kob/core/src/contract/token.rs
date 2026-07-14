use crate::primitives::push_data;

// ============================================================================
// KCC20 Standard State Header
// ============================================================================
//
// Source: "Fungible Token Covenant Specification (KCC20)" by Manyfest,
// https://kas-smiths.org/t/fungible-token-covenant-specification-kcc20/8
// (opening post + the "SilverScript Interface" / "Token Descriptor"
// follow-ups in the same thread).
//
// Every KCC20-conformant token state begins with three canonical leading
// fields, in this exact order: owner_identifier (32B), identifier_type (1B),
// amount (integer; KOB uses an 8-byte little-endian u64 where encoded).
//
// Decision -- amount is NOT embedded in token_unit's script bytes:
// KOB's `token_unit` covenant derives its P2SH address deterministically
// from the redeemScript content alone (standard P2SH semantics), and the
// whole DEX (cli/deploy.rs, cli/swap.rs, cli/dca.rs, cli/token.rs,
// engine/chain/deploy.rs) discovers a wallet's token_unit UTXOs by
// computing that address from the owner's pubkey ALONE and querying the
// node for whatever UTXOs currently sit there. If `amount` were literal
// script bytes, every distinct balance would hash to a different address,
// breaking that discovery mechanism across the entire codebase (the same
// way it would if `owner_identifier` changed). Rearchitecting UTXO
// discovery to scan-by-covenant-id instead is a large, separate change
// (a new chain-indexing Reader) that is out of scope for a conformance
// pass and risks inventing features beyond the spec's minimal ask.
//
// KOB instead maps KCC20 `amount` onto the token_unit UTXO's native sompi
// value -- exactly what KOB's token_unit already did before this change
// ("Amount of sompi to allocate to the new token_unit output"). This is a
// transparent, on-chain-visible mapping (the value is a plain field of
// the transaction output, not hidden), just not a literal byte range
// inside the redeemScript. `identifier_type`, by contrast, IS a script
// byte: it is a fixed constant for a given covenant body, so embedding it
// does not fragment addressing (see `build_token_unit_redeem_script`).
//
// See KCC20_SYNC_STATUS.md ("KCC20 amount mapping") for the decision
// record.

/// KCC20 `identifier_type` enum values (Standard State Header field 2).
pub mod identifier_type {
    /// owner_identifier is a 32-byte Schnorr public key.
    pub const PUBKEY: u8 = 0x00;
    /// owner_identifier is a 32-byte hash of a locking script.
    pub const SCRIPT_HASH: u8 = 0x01;
    /// owner_identifier is a 32-byte covenant id.
    pub const COVENANT_ID: u8 = 0x02;
}

/// Decoded KCC20 Standard State Header: `owner_identifier`, `identifier_type`,
/// `amount`. See the module-level decision note for why `amount` is sourced
/// from the UTXO's native value rather than from script bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kcc20StateHeader {
    pub owner_identifier: [u8; 32],
    pub identifier_type: u8,
    pub amount: u64,
}

impl Kcc20StateHeader {
    /// Size, in bytes, of the script-encoded portion of the header --
    /// `owner_identifier` + `identifier_type` (push opcodes included):
    /// `[0x20]+32 + [0x01]+1` = 34 bytes. `amount` is not part of this
    /// count (see module-level decision note).
    pub const SCRIPT_ENCODED_LEN: usize = 34;

    pub fn new(owner_identifier: [u8; 32], identifier_type: u8, amount: u64) -> Self {
        Self { owner_identifier, identifier_type, amount }
    }

    /// Encode the script-encoded portion of the header (the "Writer" side):
    /// `[0x20][owner_identifier 32B][0x01][identifier_type 1B]`.
    /// `amount` is intentionally not written here.
    pub fn encode_script(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SCRIPT_ENCODED_LEN);
        out.push(0x20);
        out.extend_from_slice(&self.owner_identifier);
        out.push(0x01);
        out.push(self.identifier_type);
        out
    }

    /// Decode the leading header fields from a redeemScript (the "Reader"
    /// side), combined with the UTXO's native value for `amount`. Bytes
    /// beyond `SCRIPT_ENCODED_LEN` (body opcodes or extension fields) are
    /// ignored. Returns `None` if the input is too short or the push
    /// opcodes don't match the expected layout.
    pub fn decode(script: &[u8], utxo_value: u64) -> Option<Self> {
        if script.len() < Self::SCRIPT_ENCODED_LEN {
            return None;
        }
        if script[0] != 0x20 || script[33] != 0x01 {
            return None;
        }
        let mut owner_identifier = [0u8; 32];
        owner_identifier.copy_from_slice(&script[1..33]);
        let identifier_type = script[34];
        Some(Self { owner_identifier, identifier_type, amount: utxo_value })
    }
}

// ============================================================================
// KCC20 Token Descriptor
// ============================================================================

/// A single named field in a KCC20 `state_layout` descriptor.
#[derive(Debug, Clone, Copy)]
pub struct StateField {
    pub name: &'static str,
    pub len: usize,
    /// Whether this field is literally encoded in the covenant's script
    /// bytes (`true`), or mapped from a different on-chain source such as
    /// the UTXO's native value (`false`) -- see the module-level decision
    /// note above `Kcc20StateHeader`.
    pub in_script: bool,
}

/// KCC20 Token Descriptor: `prefix`/`suffix` are the script bytes before and
/// after the encoded token state, `state_layout` describes how raw state
/// bytes decode/encode, and the two `*_entrypoint_selector` fields identify
/// the compiled transfer paths (per the spec's Token Descriptor definition).
pub struct TokenDescriptor {
    /// Script bytes before the encoded token state. KOB's redeemScript
    /// layout is always `state || body`, so this is always empty.
    pub prefix: &'static [u8],
    /// Script bytes after the encoded token state (the covenant body).
    pub suffix: &'static [u8],
    /// Ordered field layout of the encoded state (header first, then any
    /// extension fields).
    pub state_layout: &'static [StateField],
    /// Selector identifying the compiled transfer path for the
    /// covenant-input leader (by convention, the first covenant input).
    /// `None` means the covenant is single-entrypoint and no selector byte
    /// is pushed at all -- see the decision note below.
    pub leader_entrypoint_selector: Option<u8>,
    /// Selector for delegator (non-leader) covenant inputs in the same
    /// transaction. `None` means delegator dispatch is not implemented.
    pub delegator_entrypoint_selector: Option<u8>,
    /// KCC20 extension identifiers this token declares support for.
    pub optional_extensions: &'static [&'static str],
}

/// `token_unit` KCC20 state_layout: the Standard State Header, plus a
/// documented-but-unimplemented reservation for a future nonce extension
/// (see the reservation note near `TOKEN_UNIT_BODY`). The reserved slot is
/// commented out: it is NOT part of the actual on-chain encoding today, and
/// `Kcc20StateHeader::{encode_script,decode}` do not read or write it.
pub const TOKEN_UNIT_STATE_LAYOUT: &[StateField] = &[
    StateField { name: "owner_identifier", len: 32, in_script: true },
    StateField { name: "identifier_type", len: 1, in_script: true },
    StateField { name: "amount", len: 8, in_script: false },
    // RESERVED (not implemented): StateField { name: "nonce", len: 8, in_script: true }
    // Candidate trailing field for a future `kcc20_nonce_v1` per-UTXO
    // replay-protection extension. See NONCE reservation note below.
];

/// KCC20 Token Descriptor instance describing KOB's `token_unit` covenant.
///
/// Decision (open spec thread question -- see Shawn/KRON's post about
/// `without_selector: true` single-entrypoint covenants): `token_unit`
/// exposes exactly one method (transfer; mint/burn authority lives in the
/// separate `token_mint` covenant), so it is single-entrypoint. Simplest
/// option chosen: `leader_entrypoint_selector = None`, i.e. no selector
/// byte is pushed in the sigscript at all, rather than inventing an
/// empty-string or explicit-null selector encoding. This matches KOB's
/// existing `build_token_unit_sigscript`, which pushes only
/// `[sig][pushData(redeem_script)]` with no selector.
pub const KCC20_TOKEN_UNIT_DESCRIPTOR: TokenDescriptor = TokenDescriptor {
    prefix: &[],
    suffix: TOKEN_UNIT_BODY,
    state_layout: TOKEN_UNIT_STATE_LAYOUT,
    leader_entrypoint_selector: None,
    delegator_entrypoint_selector: None,
    optional_extensions: &[],
};

// ============================================================================
// token_mint (admin mint/burn authority covenant -- unchanged, out of KCC20
// scope: it is never a transferable token UTXO and carries no KCC20 state
// header of its own; only `token_unit` is the KCC20-facing token state)
// ============================================================================

/// token_mint body bytecode (14 bytes).
///
/// Selector-based dispatch via Op1 OpRoll:
/// - Op1 (mint): self-continuation (output[0] SPK == input SPK) + admin CheckSigVerify
/// - Op0 (burn): admin CheckSigVerify only, no continuation
///
/// State: [0x20][admin_pk 32B] = 33B
/// Total redeemScript: 33 (state) + 14 (body) = 47 bytes
///
/// Sigscript (mint): [41 <sig 64B> 01] [51] [pushData(RS 47B)]   = 116B
/// Sigscript (burn): [41 <sig 64B> 01] [00] [pushData(RS 47B)]   = 116B
pub const TOKEN_MINT_BODY: &[u8] = &[
    0x51, 0x7a,       // Op1 OpRoll (bring selector to top)
    0x63,             // OpIf (truthy = mint)
    0x00, 0xc3,       // Op0 OpTxOutputSpk (output[0] SPK)
    0xb9, 0xbf,       // OpTxInputIndex OpTxInputSpk (this input's SPK)
    0x87, 0x69,       // OpEqual OpVerify (self-continuation check)
    0xad,             // OpCheckSigVerify (admin sig)
    0x67,             // OpElse (burn)
    0xad,             // OpCheckSigVerify (admin sig)
    0x68,             // OpEndIf
    0x51,             // Op1 (TRUE)
];

/// Build token_mint redeemScript (47 bytes).
///
/// State (33B): [0x20][admin_pk 32B]
/// Body (14B): TOKEN_MINT_BODY
pub fn build_token_mint_redeem_script(admin_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut rs = Vec::with_capacity(47);
    rs.push(0x20);
    rs.extend_from_slice(admin_pubkey);
    rs.extend_from_slice(TOKEN_MINT_BODY);
    rs
}

/// Build token_mint mint sigscript: [push sig(65B)] [Op1] [pushData(RS)]
///
/// Op1 selector triggers the mint path (self-continuation + admin sig).
/// sigOpCount = 1 for the input.
pub fn build_token_mint_sigscript(signature: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.push(65); // length prefix for sig
    ss.extend_from_slice(&sig_with_type);
    ss.push(0x51); // Op1 (selector = mint)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build token_mint burn sigscript: [push sig(65B)] [Op0] [pushData(RS)]
///
/// Op0 selector triggers the burn path (admin sig only, no continuation).
pub fn build_token_burn_sigscript(signature: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.push(65); // length prefix for sig
    ss.extend_from_slice(&sig_with_type);
    ss.push(0x00); // Op0 (selector = burn)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// ============================================================================
// token_unit (transferable token state -- KCC20 Standard State Header)
// ============================================================================

/// token_unit body bytecode (3 bytes) -- KCC20-conformant.
///
/// State section is the script-encoded portion of the KCC20 Standard State
/// Header (34B, see `Kcc20StateHeader`): owner_identifier, identifier_type.
/// Only `identifier_type == identifier_type::PUBKEY` is currently
/// supported by this body (owner_identifier is checked directly as a
/// Schnorr pubkey); other identifier types are reserved by the spec but
/// unimplemented here.
///
/// Script pushes state fields in header order (owner_identifier first,
/// identifier_type last), so after the state section the stack holds, top
/// to bottom: identifier_type, owner_identifier, <sig from sigscript>. The
/// body drops the header field not needed by this simple owner-signature
/// check (identifier_type) and then verifies ownership.
///
/// State (34B): script-encoded KCC20 Standard State Header
/// Total redeemScript: 34 (state) + 3 (body) = 37 bytes
///
/// Sigscript (transfer): [41 <sig 64B> 01] [pushData(RS 37B)]   = 104B
pub const TOKEN_UNIT_BODY: &[u8] = &[
    0x75,             // OpDrop (identifier_type)
    0xad,             // OpCheckSigVerify (owner_identifier as pubkey)
    0x51,             // Op1 (TRUE)
];

// --- KCC20 nonce extension reservation -------------------------------------
//
// A future `kcc20_nonce_v1`-style extension could append a per-UTXO replay
// nonce as an additional trailing state field after `identifier_type`
// (the last script-encoded header field):
//
//   ...[0x01][identifier_type 1B] [0x08][nonce LE 8B]
//
// This is a documentation-only reservation: no nonce is encoded, checked,
// verified, or incremented anywhere in KOB today. Reserving the slot here
// (rather than silently repurposing bytes later) means a real nonce
// extension can append after the header without reordering or resizing the
// fields Readers/Writers already depend on. See KCC20_SYNC_STATUS.md
// ("KCC20 nonce reservation") for the decision record.
pub const NONCE_EXT_ID: &str = "kcc20_nonce_v1";
pub const NONCE_EXT_OFFSET: usize = Kcc20StateHeader::SCRIPT_ENCODED_LEN;
pub const NONCE_EXT_LEN: usize = 8;

/// Build a KCC20-conformant token_unit redeemScript (37 bytes).
///
/// State (34B): script-encoded KCC20 Standard State Header --
/// owner_identifier (32B), identifier_type (1B, always
/// `identifier_type::PUBKEY` for this body).
/// Body (3B): TOKEN_UNIT_BODY
///
/// `amount` is not a parameter here -- see the module-level decision note
/// on why KCC20 `amount` is mapped onto the UTXO's native value rather
/// than embedded in the script (this also keeps the redeemScript, and
/// hence the P2SH address, a pure function of `owner_pubkey` alone, which
/// the rest of KOB relies on for UTXO discovery).
pub fn build_token_unit_redeem_script(owner_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut rs = Vec::with_capacity(37);
    rs.extend_from_slice(&Kcc20StateHeader::new(*owner_pubkey, identifier_type::PUBKEY, 0).encode_script());
    rs.extend_from_slice(TOKEN_UNIT_BODY);
    rs
}

/// Decode the KCC20 Standard State Header from a token_unit redeemScript
/// plus its UTXO's native value (the "Reader" side). `utxo_value` becomes
/// the header's `amount` field (see module-level decision note). Returns
/// `None` if `script` is not a valid token_unit redeemScript (wrong length
/// or malformed header).
pub fn parse_token_unit_state(script: &[u8], utxo_value: u64) -> Option<Kcc20StateHeader> {
    if script.len() != Kcc20StateHeader::SCRIPT_ENCODED_LEN + TOKEN_UNIT_BODY.len() {
        return None;
    }
    if &script[Kcc20StateHeader::SCRIPT_ENCODED_LEN..] != TOKEN_UNIT_BODY {
        return None;
    }
    Kcc20StateHeader::decode(script, utxo_value)
}

/// Build token_unit transfer sigscript: [push sig(65B)] [pushData(RS)]
///
/// Simple owner signature. No entrypoint selector is pushed (see
/// `KCC20_TOKEN_UNIT_DESCRIPTOR::leader_entrypoint_selector` decision note).
pub fn build_token_unit_sigscript(signature: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(66 + redeem_script.len() + 3);
    ss.push(65); // length prefix for sig
    ss.extend_from_slice(&sig_with_type);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
