//! TX payload encoding and parsing for L1 order discovery.

/// KOB order payload prefix: "KOB:2:" (6 bytes, ASCII).
pub const KOB_PAYLOAD_PREFIX: &[u8] = b"KOB:2:";

/// Flags byte bit positions.
pub const PAYLOAD_FLAG_POST_ONLY: u8 = 0x01;
/// GTD (Good-Till-Date) flag: when set, 8 bytes of expiry DAA score
/// are appended after the RS data.
pub const PAYLOAD_FLAG_GTD: u8 = 0x02;
/// IFD (If-Done) flag: when set, the rs_data contains order A's RS and
/// ifd_order_b_rs contains order B's RS.
/// Format: `<a_len_u16_LE><order_a_rs><order_b_rs>`
/// Order A's bspkh must equal the SPK hash of order B's P2SH.
pub const PAYLOAD_FLAG_IFD: u8 = 0x04;

/// Parsed payload result.
#[derive(Debug, Clone)]
pub struct Payload {
    /// Raw flags byte.
    pub flags: u8,
    /// Post-only flag (bit 0 of flags).
    pub post_only: bool,
    /// GTD expiry DAA score (None = GTC, no expiry).
    pub expiry_daa: Option<u64>,
    /// RS bytes. For IFD payloads, this contains only order A's RS.
    pub rs_data: Vec<u8>,
    /// IFD order B RS (only set when PAYLOAD_FLAG_IFD is active).
    pub ifd_order_b_rs: Option<Vec<u8>>,
}

/// Build a TX payload for a single order deploy with flags.
///
/// Format: `KOB:2:<flags_byte><RS>[<expiry_daa_u64_LE>]`
///
/// Flags byte:
///   bit 0 = post_only (order must rest on the book, never match as taker)
///   bit 1 = GTD (8-byte expiry DAA score appended after RS)
///   bit 2 = IFD (order B RS appended: `<a_len_u16><order_a_rs><order_b_rs>`)
///   bits 3-7 = reserved (must be 0)
pub fn build_order_payload(rs: &[u8], post_only: bool) -> Vec<u8> {
    build_order_payload_full(rs, post_only, None)
}

/// Build a TX payload for a single order deploy with full options.
///
/// When `expiry_daa` is `Some`, the GTD flag (bit 1) is set and the 8-byte
/// LE DAA score is appended after the RS data.
pub fn build_order_payload_full(
    rs: &[u8],
    post_only: bool,
    expiry_daa: Option<u64>,
) -> Vec<u8> {
    let mut flags: u8 = 0;
    if post_only {
        flags |= PAYLOAD_FLAG_POST_ONLY;
    }
    if expiry_daa.is_some() {
        flags |= PAYLOAD_FLAG_GTD;
    }
    let gtd_len = if expiry_daa.is_some() { 8 } else { 0 };
    let mut payload = Vec::with_capacity(KOB_PAYLOAD_PREFIX.len() + 1 + rs.len() + gtd_len);
    payload.extend_from_slice(KOB_PAYLOAD_PREFIX);
    payload.push(flags);
    payload.extend_from_slice(rs);
    if let Some(daa) = expiry_daa {
        payload.extend_from_slice(&daa.to_le_bytes());
    }
    payload
}

/// Build a TX payload for an IFD deploy.
///
/// Format: `KOB:2:<flags|0x04><a_len_u16_LE><order_a_rs><order_b_rs>[<expiry_daa>]`
///
/// Order A's `bspkh` must be set to the SPK hash of order B's P2SH so the
/// covenant enforces that the fill TX output goes to order B's P2SH address.
pub fn build_ifd_order_payload(
    order_a_rs: &[u8],
    order_b_rs: &[u8],
    post_only: bool,
    expiry_daa: Option<u64>,
) -> Vec<u8> {
    let mut flags: u8 = PAYLOAD_FLAG_IFD;
    if post_only {
        flags |= PAYLOAD_FLAG_POST_ONLY;
    }
    if expiry_daa.is_some() {
        flags |= PAYLOAD_FLAG_GTD;
    }
    assert!(order_a_rs.len() <= u16::MAX as usize, "order A RS exceeds u16::MAX");
    let a_len = order_a_rs.len() as u16;
    let gtd_len = if expiry_daa.is_some() { 8 } else { 0 };
    let mut payload = Vec::with_capacity(
        KOB_PAYLOAD_PREFIX.len() + 1 + 2 + order_a_rs.len() + order_b_rs.len() + gtd_len,
    );
    payload.extend_from_slice(KOB_PAYLOAD_PREFIX);
    payload.push(flags);
    payload.extend_from_slice(&a_len.to_le_bytes());
    payload.extend_from_slice(order_a_rs);
    payload.extend_from_slice(order_b_rs);
    if let Some(daa) = expiry_daa {
        payload.extend_from_slice(&daa.to_le_bytes());
    }
    payload
}

/// Build a TX payload for an OCO deploy with flags.
///
/// Format: `KOB:2:<flags_byte><buy_rs_len as u16 LE><buy_rs><sell_rs>[<expiry_daa_u64_LE>]`
pub fn build_oco_order_payload(buy_rs: &[u8], sell_rs: &[u8], post_only: bool) -> Vec<u8> {
    build_oco_order_payload_full(buy_rs, sell_rs, post_only, None)
}

/// Build a TX payload for an OCO deploy with full options.
pub fn build_oco_order_payload_full(
    buy_rs: &[u8],
    sell_rs: &[u8],
    post_only: bool,
    expiry_daa: Option<u64>,
) -> Vec<u8> {
    let mut flags: u8 = 0;
    if post_only {
        flags |= PAYLOAD_FLAG_POST_ONLY;
    }
    if expiry_daa.is_some() {
        flags |= PAYLOAD_FLAG_GTD;
    }
    assert!(buy_rs.len() <= u16::MAX as usize, "buy RS exceeds u16::MAX");
    let buy_len = buy_rs.len() as u16;
    let gtd_len = if expiry_daa.is_some() { 8 } else { 0 };
    let mut payload = Vec::with_capacity(
        KOB_PAYLOAD_PREFIX.len() + 1 + 2 + buy_rs.len() + sell_rs.len() + gtd_len,
    );
    payload.extend_from_slice(KOB_PAYLOAD_PREFIX);
    payload.push(flags);
    payload.extend_from_slice(&buy_len.to_le_bytes());
    payload.extend_from_slice(buy_rs);
    payload.extend_from_slice(sell_rs);
    if let Some(daa) = expiry_daa {
        payload.extend_from_slice(&daa.to_le_bytes());
    }
    payload
}

/// Parse a KOB order payload, stripping the `KOB:2:` prefix.
///
/// Returns `Payload` with the flags, RS data, and optional GTD expiry.
/// Returns `None` if the payload doesn't start with `KOB:2:` or is too
/// short (needs at least prefix + 1 flags byte, plus 8 bytes if GTD flag set).
pub fn parse_order_payload(payload: &[u8]) -> Option<Payload> {
    if payload.len() < KOB_PAYLOAD_PREFIX.len() + 1 {
        return None;
    }
    if &payload[..KOB_PAYLOAD_PREFIX.len()] != KOB_PAYLOAD_PREFIX {
        return None;
    }
    let flags = payload[KOB_PAYLOAD_PREFIX.len()];
    let after_flags = &payload[KOB_PAYLOAD_PREFIX.len() + 1..];

    // Strip optional GTD trailer first
    let (body, expiry_daa) = if flags & PAYLOAD_FLAG_GTD != 0 {
        if after_flags.len() < 8 {
            return None;
        }
        let split = after_flags.len() - 8;
        let daa_bytes: [u8; 8] = after_flags[split..].try_into().ok()?;
        let daa = u64::from_le_bytes(daa_bytes);
        (&after_flags[..split], Some(daa))
    } else {
        (after_flags, None)
    };

    // IFD: <a_len_u16_LE><order_a_rs><order_b_rs>
    let (rs_data, ifd_order_b_rs) = if flags & PAYLOAD_FLAG_IFD != 0 {
        if body.len() < 2 {
            return None;
        }
        let a_len = u16::from_le_bytes([body[0], body[1]]) as usize;
        if body.len() < 2 + a_len {
            return None;
        }
        let order_a_rs = body[2..2 + a_len].to_vec();
        let order_b_rs = body[2 + a_len..].to_vec();
        if order_b_rs.is_empty() {
            return None;
        }
        (order_a_rs, Some(order_b_rs))
    } else {
        (body.to_vec(), None)
    };

    Some(Payload {
        flags,
        post_only: flags & PAYLOAD_FLAG_POST_ONLY != 0,
        expiry_daa,
        rs_data,
        ifd_order_b_rs,
    })
}
