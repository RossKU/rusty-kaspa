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

/// Push a script integer onto a sigscript buffer.
///
/// Encoding:
///   0        -> `[0x00]`             (Op0, 1 byte)
///   1..=16   -> `[0x50+n]`           (OpN, 1 byte)
///   17..=127 -> `[0x01, n]`          (data-push, 2 bytes)
///   128..=255-> `[0x02, n, 0x00]`    (data-push, 3 bytes; zero-pad high byte for sign)
///   256+     -> `[0x02, lo, hi]`     (data-push, 3 bytes, little-endian)
///
/// This enables batch transactions with more than 17 inputs/outputs,
/// where output indices can exceed the OpN range.
pub fn push_index(ss: &mut Vec<u8>, n: u16) {
    match n {
        0 => ss.push(0x00),
        1..=16 => ss.push(0x50 + n as u8),
        17..=127 => {
            ss.push(0x01); // OpData1: push next 1 byte
            ss.push(n as u8);
        }
        128..=255 => {
            // Values 128-255: MSB of low byte is set, so a 1-byte push would
            // be interpreted as negative by the script engine.  Push 2 bytes
            // with a zero high byte to keep the value positive.
            ss.push(0x02); // OpData2: push next 2 bytes
            ss.push(n as u8);
            ss.push(0x00);
        }
        _ => {
            // 256+: 2-byte little-endian
            ss.push(0x02);
            ss.push(n as u8);         // low byte
            ss.push((n >> 8) as u8);  // high byte
        }
    }
}
