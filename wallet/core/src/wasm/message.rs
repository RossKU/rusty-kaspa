use crate::imports::*;
use crate::message::*;
use kaspa_addresses::Version as AddressVersion;
use kaspa_wallet_keys::privatekey::PrivateKey;
use kaspa_wallet_keys::publickey::PublicKey;
use kaspa_wasm_core::types::HexString;

#[wasm_bindgen(typescript_custom_section)]
const TS_MESSAGE_TYPES: &'static str = r#"
/**
 * Interface declaration for {@link signMessage} function arguments.
 *
 * @category Message Signing
 */
export interface ISignMessage {
    message: string;
    privateKey: PrivateKey | string;
    noAuxRand?: boolean;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = js_sys::Object, typescript_type = "ISignMessage")]
    pub type ISignMessage;
}

/// Signs a message with the given private key
/// @category Message Signing
#[wasm_bindgen(js_name = signMessage)]
pub fn js_sign_message(value: ISignMessage) -> Result<HexString, Error> {
    if let Some(object) = Object::try_from(&value) {
        let private_key = object.cast_into::<PrivateKey>("privateKey")?;
        let raw_msg = object.get_string("message")?;
        let no_aux_rand = object.get_bool("noAuxRand").unwrap_or(false);
        let mut privkey_bytes = [0u8; 32];
        privkey_bytes.copy_from_slice(&private_key.secret_bytes());
        let pm = PersonalMessage(&raw_msg);
        let sign_options = SignMessageOptions { no_aux_rand };
        let sig_vec = sign_message(&pm, &privkey_bytes, &sign_options)?;
        privkey_bytes.zeroize();
        Ok(faster_hex::hex_string(sig_vec.as_slice()).into())
    } else {
        Err(Error::custom("Failed to parse input"))
    }
}

#[wasm_bindgen(typescript_custom_section)]
const TS_VERIFY_MESSAGE_TYPES: &'static str = r#"
/**
 * Interface declaration for {@link verifyMessage} function arguments.
 *
 * @category Message Signing
 */
export interface IVerifyMessage {
    message: string;
    signature: HexString;
    publicKey?: PublicKey | string;
    address?: Address | string;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = js_sys::Object, typescript_type = "IVerifyMessage")]
    pub type IVerifyMessage;
}

/// Verifies the signature of the given message with a public key or address.
///
/// Supply either `publicKey` or `address` (a Schnorr PubKey address).
/// When `address` is provided, the public key is extracted from it automatically.
///
/// @category Message Signing
#[wasm_bindgen(js_name = verifyMessage, skip_jsdoc)]
pub fn js_verify_message(value: IVerifyMessage) -> Result<bool, Error> {
    if let Some(object) = Object::try_from(&value) {
        let raw_msg = object.get_string("message")?;
        let signature = object.get_string("signature")?;

        let xonly_public_key = if let Ok(public_key) = object.cast_into::<PublicKey>("publicKey") {
            public_key.xonly_public_key
        } else if let Ok(address) = object.cast_into::<Address>("address") {
            if address.version != AddressVersion::PubKey {
                return Err(Error::custom("Address not supported for message verification. Only PubKey addresses are supported"));
            }
            secp256k1::XOnlyPublicKey::from_slice(&address.payload)?
        } else {
            return Err(Error::custom("publicKey or address is required"));
        };

        let pm = PersonalMessage(&raw_msg);
        let mut signature_bytes = [0u8; 64];
        faster_hex::hex_decode(signature.as_bytes(), &mut signature_bytes)?;

        Ok(verify_message(&pm, &signature_bytes.to_vec(), &xonly_public_key).is_ok())
    } else {
        Err(Error::custom("Failed to parse input"))
    }
}
