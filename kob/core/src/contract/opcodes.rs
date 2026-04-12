//! Kaspa script opcode names and script disassembly.

/// Return the human-readable name for a Kaspa script opcode byte.
pub fn opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "OP_0",
        0x01..=0x4b => "OP_DATA", // direct push (N bytes follow)
        0x4c => "OP_PUSHDATA1",
        0x4d => "OP_PUSHDATA2",
        0x4e => "OP_PUSHDATA4",
        0x4f => "OP_1NEGATE",
        0x51 => "OP_1",
        0x52 => "OP_2",
        0x53 => "OP_3",
        0x54 => "OP_4",
        0x55 => "OP_5",
        0x56 => "OP_6",
        0x57 => "OP_7",
        0x58 => "OP_8",
        0x59 => "OP_9",
        0x5a => "OP_10",
        0x5b => "OP_11",
        0x5c => "OP_12",
        0x5d => "OP_13",
        0x5e => "OP_14",
        0x5f => "OP_15",
        0x60 => "OP_16",
        // Flow control
        0x61 => "OP_NOP",
        0x63 => "OP_IF",
        0x64 => "OP_NOTIF",
        0x67 => "OP_ELSE",
        0x68 => "OP_ENDIF",
        0x69 => "OP_VERIFY",
        0x6a => "OP_RETURN",
        // Stack
        0x6b => "OP_TOALTSTACK",
        0x6c => "OP_FROMALTSTACK",
        0x6d => "OP_2DROP",
        0x6e => "OP_2DUP",
        0x6f => "OP_3DUP",
        0x73 => "OP_IFDUP",
        0x75 => "OP_DROP",
        0x76 => "OP_DUP",
        0x77 => "OP_NIP",
        0x78 => "OP_OVER",
        0x79 => "OP_PICK",
        0x7a => "OP_ROLL",
        0x7b => "OP_ROT",
        0x7c => "OP_SWAP",
        0x7d => "OP_TUCK",
        // Splice
        0x82 => "OP_SIZE",
        // Bitwise
        0x87 => "OP_EQUAL",
        0x88 => "OP_EQUALVERIFY",
        // Arithmetic
        0x8b => "OP_1ADD",
        0x8c => "OP_1SUB",
        0x8f => "OP_NEGATE",
        0x90 => "OP_ABS",
        0x91 => "OP_NOT",
        0x92 => "OP_0NOTEQUAL",
        0x93 => "OP_ADD",
        0x94 => "OP_SUB",
        0x95 => "OP_MUL",
        0x96 => "OP_DIV",
        0x97 => "OP_MOD",
        0x9a => "OP_BOOLAND",
        0x9b => "OP_BOOLOR",
        0x9c => "OP_NUMEQUAL",
        0x9d => "OP_NUMEQUALVERIFY",
        0x9e => "OP_NUMNOTEQUAL",
        0x9f => "OP_LT",
        0xa0 => "OP_GT",
        0xa1 => "OP_LTE",
        0xa2 => "OP_GTE",
        0xa3 => "OP_MIN",
        0xa4 => "OP_MAX",
        0xa5 => "OP_WITHIN",
        // ZK
        0xa6 => "OP_ZKPRECOMPILE",
        // Crypto
        0xa8 => "OP_SHA256",
        0xaa => "OP_BLAKE2B",
        0xab => "OP_CODESEPARATOR",
        0xac => "OP_CHECKSIG",
        0xad => "OP_CHECKSIGVERIFY",
        0xae => "OP_CHECKMULTISIG",
        0xaf => "OP_CHECKMULTISIGVERIFY",
        // Lock time
        0xb0 => "OP_CLTV",
        0xb1 => "OP_OUTPUTCOUNT",
        0xb2 => "OP_CSV",
        0xb3 => "OP_INPUTCOUNT",
        0xb4 => "OP_INPUTINDEX",
        0xb5 => "OP_TXLOCKTIME",
        // TX introspection
        0xb9 => "OP_TXINPUTINDEX",
        0xbe => "OP_TXINPUTAMOUNT",
        0xbf => "OP_TXINPUTSPK",
        0xc2 => "OP_TXOUTPUTAMOUNT",
        0xc3 => "OP_TXOUTPUTSPK",
        0xc9 => "OP_TXINPUTSIGSIGLEN",
        // Subtraction
        0xc7 => "OP_SUBTRACTOUTPUTS",
        // Covenant introspection
        0xcf => "OP_INPUTCOVENANTID",
        0xd0 => "OP_COVINPUTCOUNT",
        0xd1 => "OP_COVINPUTIDX",
        0xd2 => "OP_COVOUTCOUNT",
        _ => "OP_UNKNOWN",
    }
}

/// A single element in a disassembled script.
#[derive(Debug)]
pub enum ScriptElement {
    /// Opcode with no inline data.
    Op(u8),
    /// Push data: the opcode byte and the pushed bytes.
    Push(u8, Vec<u8>),
}

/// Disassemble a raw script into a sequence of opcodes and push-data elements.
///
/// Returns a vector of `ScriptElement` entries. On malformed input the
/// disassembly stops and returns what was parsed so far.
pub fn disassemble(script: &[u8]) -> Vec<ScriptElement> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        match op {
            // Direct push: next N bytes
            0x01..=0x4b => {
                let n = op as usize;
                if i + 1 + n > script.len() {
                    out.push(ScriptElement::Op(op)); // truncated
                    break;
                }
                out.push(ScriptElement::Push(op, script[i + 1..i + 1 + n].to_vec()));
                i += 1 + n;
            }
            // OP_PUSHDATA1
            0x4c => {
                if i + 1 >= script.len() { break; }
                let n = script[i + 1] as usize;
                if i + 2 + n > script.len() { break; }
                out.push(ScriptElement::Push(op, script[i + 2..i + 2 + n].to_vec()));
                i += 2 + n;
            }
            // OP_PUSHDATA2
            0x4d => {
                if i + 2 >= script.len() { break; }
                let n = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                if i + 3 + n > script.len() { break; }
                out.push(ScriptElement::Push(op, script[i + 3..i + 3 + n].to_vec()));
                i += 3 + n;
            }
            // OP_PUSHDATA4
            0x4e => {
                if i + 4 >= script.len() { break; }
                let n = u32::from_le_bytes([
                    script[i + 1], script[i + 2], script[i + 3], script[i + 4],
                ]) as usize;
                if i + 5 + n > script.len() { break; }
                out.push(ScriptElement::Push(op, script[i + 5..i + 5 + n].to_vec()));
                i += 5 + n;
            }
            // All other opcodes
            _ => {
                out.push(ScriptElement::Op(op));
                i += 1;
            }
        }
    }
    out
}

/// Format a disassembled script as a single-line human-readable string.
///
/// Push data is shown as `PUSH<N>(hex...)` (truncated to 16 bytes for display).
/// Opcodes are shown by name.
pub fn format_script(script: &[u8]) -> String {
    let elements = disassemble(script);
    let mut parts = Vec::with_capacity(elements.len());
    for elem in &elements {
        match elem {
            ScriptElement::Op(op) => {
                parts.push(opcode_name(*op).to_string());
            }
            ScriptElement::Push(op, data) => {
                let display_hex = if data.len() <= 16 {
                    hex::encode(data)
                } else {
                    format!("{}...({}B)", hex::encode(&data[..16]), data.len())
                };
                if *op <= 0x4b {
                    // Direct push
                    parts.push(format!("PUSH{}({})", data.len(), display_hex));
                } else {
                    parts.push(format!("{}({})", opcode_name(*op), display_hex));
                }
            }
        }
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_names() {
        assert_eq!(opcode_name(0x00), "OP_0");
        assert_eq!(opcode_name(0x51), "OP_1");
        assert_eq!(opcode_name(0x76), "OP_DUP");
        assert_eq!(opcode_name(0xac), "OP_CHECKSIG");
        assert_eq!(opcode_name(0xb2), "OP_CSV");
        assert_eq!(opcode_name(0xa6), "OP_ZKPRECOMPILE");
        assert_eq!(opcode_name(0xbf), "OP_TXINPUTSPK");
    }

    #[test]
    fn test_disassemble_simple() {
        // OP_1 OP_DUP OP_EQUAL
        let script = vec![0x51, 0x76, 0x87];
        let elements = disassemble(&script);
        assert_eq!(elements.len(), 3);
        assert!(matches!(elements[0], ScriptElement::Op(0x51)));
        assert!(matches!(elements[1], ScriptElement::Op(0x76)));
        assert!(matches!(elements[2], ScriptElement::Op(0x87)));
    }

    #[test]
    fn test_disassemble_push_data() {
        // PUSH2(aabb) OP_1
        let script = vec![0x02, 0xaa, 0xbb, 0x51];
        let elements = disassemble(&script);
        assert_eq!(elements.len(), 2);
        match &elements[0] {
            ScriptElement::Push(0x02, data) => assert_eq!(data, &[0xaa, 0xbb]),
            _ => panic!("expected push"),
        }
        assert!(matches!(elements[1], ScriptElement::Op(0x51)));
    }

    #[test]
    fn test_disassemble_pushdata1() {
        // OP_PUSHDATA1(len=3, data=aabbcc)
        let script = vec![0x4c, 0x03, 0xaa, 0xbb, 0xcc];
        let elements = disassemble(&script);
        assert_eq!(elements.len(), 1);
        match &elements[0] {
            ScriptElement::Push(0x4c, data) => assert_eq!(data, &[0xaa, 0xbb, 0xcc]),
            _ => panic!("expected pushdata1"),
        }
    }

    #[test]
    fn test_format_script() {
        let script = vec![0x51, 0x02, 0xaa, 0xbb, 0x76, 0xac];
        let formatted = format_script(&script);
        assert_eq!(formatted, "OP_1 PUSH2(aabb) OP_DUP OP_CHECKSIG");
    }

    #[test]
    fn test_format_large_push() {
        // PUSH32 with 32 bytes of 0xff
        let mut script = vec![0x20]; // 0x20 = 32
        script.extend_from_slice(&[0xff; 32]);
        let formatted = format_script(&script);
        assert!(formatted.contains("PUSH32(ffffffffffffffffffffffffffffffff...(32B))"));
    }
}
