use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nddev_device_sync_application::identity::{
    IdentityCrypto, IdentityError, ProtectedDigest, SecretText,
};
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct Crypto {
    key: hmac::Key,
}
impl Crypto {
    pub fn new(encoded: &str) -> Result<Self, IdentityError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| IdentityError::InvalidInput)?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
            return Err(IdentityError::InvalidInput);
        }
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &bytes),
        })
    }
}
pub fn equal(left: &ProtectedDigest, right: &ProtectedDigest) -> bool {
    bool::from(left.0.ct_eq(&right.0))
}
impl IdentityCrypto for Crypto {
    fn token(&self) -> Result<SecretText, IdentityError> {
        let mut bytes = [0; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| IdentityError::Unavailable)?;
        Ok(SecretText::new(URL_SAFE_NO_PAD.encode(bytes)))
    }
    fn otp(&self) -> Result<SecretText, IdentityError> {
        // Rejection avoids modulo bias. Even entropy-provider retries have a
        // terminal bound; eight failures report unavailable rather than looping.
        for _ in 0..8 {
            let mut bytes = [0; 4];
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| IdentityError::Unavailable)?;
            let value = u32::from_be_bytes(bytes);
            if value < 4_200_000_000 {
                return Ok(SecretText::new(format!("{:08}", value % 100_000_000)));
            }
        }
        Err(IdentityError::Unavailable)
    }
    fn protect(&self, purpose: &'static str, parts: &[&[u8]]) -> ProtectedDigest {
        let mut context = hmac::Context::with_key(&self.key);
        context.update(b"NDS-IDENTITY-V2\0");
        for part in std::iter::once(purpose.as_bytes()).chain(parts.iter().copied()) {
            context.update(&(part.len() as u64).to_be_bytes());
            context.update(part);
        }
        let tag = context.sign();
        let mut bytes = [0; 32];
        bytes.copy_from_slice(tag.as_ref());
        ProtectedDigest(bytes)
    }
    fn pkce_challenge(&self, verifier: &SecretText) -> String {
        URL_SAFE_NO_PAD
            .encode(digest::digest(&digest::SHA256, verifier.expose().as_bytes()).as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cryptographic_material_is_canonical_and_pkce_matches_rfc7636() {
        let mut pepper = [0; 32];
        SystemRandom::new().fill(&mut pepper).unwrap();
        let crypto = Crypto::new(&URL_SAFE_NO_PAD.encode(pepper)).unwrap();
        let first = crypto.token().unwrap();
        let second = crypto.token().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(first.expose()).unwrap().len(), 32);
        assert_ne!(first.expose(), second.expose());
        let code = crypto.otp().unwrap();
        assert_eq!(code.expose().len(), 8);
        assert!(code.expose().bytes().all(|byte| byte.is_ascii_digit()));
        assert!(!format!("{first:?} {code:?}").contains(first.expose()));
        let verifier = SecretText::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into());
        assert_eq!(
            crypto.pkce_challenge(&verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(!equal(
            &crypto.protect("a", &[b"bc"]),
            &crypto.protect("ab", &[b"c"])
        ));
        assert!(!equal(
            &crypto.protect("a", &[b"b", b"c"]),
            &crypto.protect("a", &[b"bc"])
        ));
        assert!(equal(
            &crypto.protect("a", &[b"b"]),
            &crypto.protect("a", &[b"b"])
        ));
    }
}
