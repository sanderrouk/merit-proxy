use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub fn sign(api_id: &str, key: &str, timestamp: &str, body: &[u8]) -> Zeroizing<String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(api_id.as_bytes());
    mac.update(timestamp.as_bytes());
    mac.update(body);
    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_independent_openssl_vector() {
        assert_eq!(
            &*sign(
                "my-api-id",
                "my-api-key",
                "20260913120000",
                br#"{"Id":"x"}"#
            ),
            "S/LZwmcec9KXl8Cgix4/qwRbfniZ4aFF29akcs1iaFo="
        );
    }

    #[test]
    fn whitespace_and_unicode_are_signed_as_transmitted() {
        assert_ne!(
            *sign("id", "key", "20261110080000", b"{}"),
            *sign("id", "key", "20261110080000", b"{}\n")
        );
        assert_ne!(
            *sign(
                "id",
                "key",
                "20261110080000",
                "{\"name\":\"Õie\"}".as_bytes()
            ),
            *sign("id", "key", "20261110080000", br#"{"name":"\u00d5ie"}"#)
        );
    }
}
