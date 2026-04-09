/// Compute greatest common divisor of two unsigned integers (Euclidean algorithm).
pub(crate) fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Convert an integer (0..=16) to the corresponding OpN opcode.
///
/// Op0 = 0x00, Op1 = 0x51, Op2 = 0x52, ..., Op16 = 0x60.
pub(crate) fn opn(n: u8) -> u8 {
    match n {
        0 => 0x00,
        1..=16 => 0x50 + n,
        _ => panic!("OpN index out of range: {} (must be 0..=16)", n),
    }
}
