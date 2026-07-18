//! KCC20 Descriptor (kcc-0020 "## Descriptor"):
//!
//! ```text
//! KCC20Descriptor {
//!     prefix: bytes
//!     suffix: bytes
//!     extended_state_layout: ExtendedStateLayout | none
//!     kcc20_extensions: ExtensionId[]
//! }
//! ```
//!
//! ## ISSUE: no wire format is defined
//!
//! Unlike kcc-0001, which ships byte-exact conformance vectors (§11) for
//! every wire concept it introduces (state encoding, template hashes,
//! dispatch tags, the hash-committed virtual-element scheme, ...),
//! kcc-0020 never defines a serialized/wire encoding for `KCC20Descriptor`
//! itself: no field order convention (is it KCC1 §5.6 record-lowered? Over
//! what push encoding?), no length-prefixing for `prefix`/`suffix`, no
//! discriminant for `ExtendedStateLayout | none`, no encoding for
//! `ExtensionId` (are these UTF-8 strings? Fixed 4-byte tags analogous to a
//! dispatch tag, given "versioned `ExtensionId`" and the one example so far,
//! `kcc20_borrowed_receive_v1`, being a bare identifier string?). kcc-0020
//! only says "The descriptor must be published so tooling can identify the
//! covenant" -- "published" how, and in what byte format, is unspecified.
//!
//! This module therefore defines only the in-memory Rust SHAPE, matching
//! the pseudocode field-for-field. It deliberately exposes no
//! `encode`/`decode`: inventing a wire format here would just be KOB's own
//! private convention masquerading as spec conformance, which is exactly
//! the kind of invented-behavior this implementation wave is supposed to
//! avoid (see the top-level task's "課題抽出" framing) -- this gap belongs
//! in the ISSUE list, not silently resolved by one Rust struct's `Vec<u8>`
//! choices.
//!
//! `crate::contract::token::TokenDescriptor` is a related, PRE-EXISTING,
//! unchanged KOB type describing the same kcc-0020 concept for the current
//! `token_unit` covenant; it is KOB's own ad hoc struct shape (predates this
//! module) and is not reused here, to keep this module's shape a direct,
//! uneditorialized transcription of kcc-0020's own pseudocode.

/// One field of an `ExtendedStateLayout` (kcc-0020's example:
/// `{ color: byte, is_minter: boolean }`).
///
/// `width` is the field's fixed payload width in bytes. kcc-0020's own
/// example only uses fixed-width leaf types (`byte`, `boolean`), so a fixed
/// width is sufficient to describe every case the spec text actually shows;
/// see the module ISSUE note on the layout's encoding being otherwise
/// unspecified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedStateFieldSpec {
    pub name: &'static str,
    pub width: usize,
}

/// Describes the shape of the token-specific state committed by
/// `extended_state_digest` (kcc-0020 "## State Extendability").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedStateLayout {
    pub fields: &'static [ExtendedStateFieldSpec],
}

/// `KCC20Descriptor` (kcc-0020 "## Descriptor"), in-memory shape only (see
/// module doc for why no wire encoding is provided).
#[derive(Debug, Clone, Copy)]
pub struct Kcc20Descriptor {
    /// Script bytes before the encoded token state (kcc-0001 §8
    /// `template.prefix`).
    pub prefix: &'static [u8],
    /// Script bytes after the encoded token state (kcc-0001 §8
    /// `template.suffix`) -- the covenant body.
    pub suffix: &'static [u8],
    /// `None` when the covenant defines no token-specific extended state
    /// (kcc-0020: "`ExtendedStateLayout | none`").
    pub extended_state_layout: Option<ExtendedStateLayout>,
    /// Declared `kcc20_extensions` (kcc-0020: "The field may be omitted when
    /// the covenant implements no standardized KCC20 extensions" -- modeled
    /// here as an empty slice rather than a separate `Option`, since an
    /// omitted field and an explicitly-empty list are not observably
    /// different in this in-memory shape; see ISSUE list on whether the
    /// real wire format needs to distinguish them).
    pub kcc20_extensions: &'static [&'static str],
}

impl Kcc20Descriptor {
    /// Total encoded-state length this descriptor implies for the standard
    /// `Kcc20State` header alone (i.e. NOT including any extended state) --
    /// `super::state::Kcc20State::ENCODED_LEN` bytes, always at
    /// `[prefix.len(), prefix.len() + Kcc20State::ENCODED_LEN)` within the
    /// full redeem script, per kcc-0001 §8's `state.start`/`state.len`
    /// scheme.
    pub const fn standard_state_len() -> usize {
        super::state::Kcc20State::ENCODED_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::kcc20::state::Kcc20State;

    const EXAMPLE_EXTENDED_LAYOUT: ExtendedStateLayout = ExtendedStateLayout {
        fields: &[
            ExtendedStateFieldSpec { name: "color", width: 1 },
            ExtendedStateFieldSpec { name: "is_minter", width: 1 },
        ],
    };

    const EXAMPLE_DESCRIPTOR: Kcc20Descriptor = Kcc20Descriptor {
        prefix: &[],
        suffix: &[0x51], // stand-in body
        extended_state_layout: Some(EXAMPLE_EXTENDED_LAYOUT),
        kcc20_extensions: &["kcc20_borrowed_receive_v1"],
    };

    #[test]
    fn descriptor_shape_matches_kcc20_pseudocode_fields() {
        assert_eq!(EXAMPLE_DESCRIPTOR.prefix, &[] as &[u8]);
        assert_eq!(EXAMPLE_DESCRIPTOR.suffix, &[0x51]);
        assert!(EXAMPLE_DESCRIPTOR.extended_state_layout.is_some());
        assert_eq!(EXAMPLE_DESCRIPTOR.kcc20_extensions, &["kcc20_borrowed_receive_v1"]);
    }

    #[test]
    fn extended_state_layout_may_be_none() {
        let d = Kcc20Descriptor {
            prefix: &[],
            suffix: &[0x51],
            extended_state_layout: None,
            kcc20_extensions: &[],
        };
        assert!(d.extended_state_layout.is_none());
        assert!(d.kcc20_extensions.is_empty());
    }

    #[test]
    fn standard_state_len_matches_kcc20_state_encoded_len() {
        assert_eq!(Kcc20Descriptor::standard_state_len(), Kcc20State::ENCODED_LEN);
        assert_eq!(Kcc20Descriptor::standard_state_len(), 77);
    }
}
