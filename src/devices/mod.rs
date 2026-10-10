pub mod http;
mod store;

use crate::identity::crypto::Crypto;
use ed25519_dalek::{Signature, VerifyingKey};
use nddev_device_sync_application::devices::{
    DeviceError, DeviceService, EnrollmentChallenge, EnrollmentCrypto, PublicDeviceKey,
};
use ring::rand::{SecureRandom, SystemRandom};

pub type Service = DeviceService<store::Store, Crypto>;

pub fn initialize(pool: sqlx::PgPool, crypto: Crypto) -> Service {
    DeviceService::new(store::Store::new(pool, crypto.clone()), crypto)
}

impl EnrollmentCrypto for Crypto {
    fn valid_public_key(&self, key: &PublicDeviceKey) -> bool {
        verifying_key(key).is_some()
    }
    fn random_challenge(&self) -> Result<[u8; 32], DeviceError> {
        let mut bytes = [0; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| DeviceError::Unavailable)?;
        Ok(bytes)
    }
    fn verify_proof(&self, challenge: &EnrollmentChallenge, signature: &[u8; 64]) -> bool {
        verifying_key(&challenge.device.public_key).is_some_and(|key| {
            key.verify_strict(
                &challenge.signing_bytes(),
                &Signature::from_bytes(signature),
            )
            .is_ok()
        })
    }
}

fn verifying_key(key: &PublicDeviceKey) -> Option<VerifyingKey> {
    let verified = VerifyingKey::from_bytes(&key.0).ok()?;
    let point = verified.to_edwards();
    if verified.is_weak() || !point.is_torsion_free() || point.compress().as_bytes() != &key.0 {
        return None;
    }
    Some(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use nddev_device_sync_application::{
        devices::*,
        identity::{AuthMethod, Owner, ProtectedDigest, Session, TenantId, UserId},
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn material() -> (Crypto, EnrollmentChallenge, Ed25519KeyPair) {
        let random = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let mut pepper = [0; 32];
        random.fill(&mut pepper).unwrap();
        let crypto = Crypto::new(&URL_SAFE_NO_PAD.encode(pepper)).unwrap();
        let owner = Owner {
            user_id: UserId::new("synthetic-owner").unwrap(),
            tenant_id: TenantId::new("synthetic-tenant").unwrap(),
        };
        let authorization = AuthenticatedSession {
            session: Session::new(owner.clone(), AuthMethod::EmailOtp, 0).unwrap(),
            binding: ProtectedDigest([7; 32]),
        };
        let device = Device {
            id: DeviceId::new("synthetic-device").unwrap(),
            owner,
            platform: DevicePlatform::Android,
            name: DeviceName::new("Synthetic".into()).unwrap(),
            public_key: PublicDeviceKey(pair.public_key().as_ref().try_into().unwrap()),
            status: DeviceStatus::Active,
            created_at_ms: 0,
        };
        let challenge = EnrollmentChallenge::new(
            "synthetic-challenge".into(),
            device,
            &authorization,
            crypto.random_challenge().unwrap(),
            0,
        )
        .unwrap();
        (crypto, challenge, pair)
    }

    #[test]
    fn real_ed25519_signature_is_bound_to_the_enrollment_domain_and_nonce() {
        let (crypto, mut challenge, pair) = material();
        assert!(crypto.valid_public_key(&challenge.device.public_key));
        let signature = pair
            .sign(&challenge.signing_bytes())
            .as_ref()
            .try_into()
            .unwrap();
        assert!(crypto.verify_proof(&challenge, &signature));
        challenge.challenge[0] ^= 1;
        assert!(!crypto.verify_proof(&challenge, &signature));
        let unprefixed = pair.sign(&challenge.challenge).as_ref().try_into().unwrap();
        assert!(!crypto.verify_proof(&challenge, &unprefixed));
    }

    #[test]
    fn weak_mixed_order_and_noncanonical_public_keys_are_rejected() {
        let (crypto, mut challenge, _) = material();
        let mut identity = [0; 32];
        identity[0] = 1;
        let mut noncanonical = [0xff; 32];
        noncanonical[0] = 0xee;
        noncanonical[31] = 0x7f;
        let torsion = VerifyingKey::from_bytes(&[0; 32]).unwrap().to_edwards();
        let mixed = (VerifyingKey::from_bytes(&challenge.device.public_key.0)
            .unwrap()
            .to_edwards()
            + torsion)
            .compress()
            .to_bytes();
        let mut forged = [0; 64];
        forged[0] = 1; // R=identity, S=0: no private signing key.
        for bytes in [identity, [0; 32], noncanonical, mixed] {
            challenge.device.public_key = PublicDeviceKey(bytes);
            assert!(!crypto.valid_public_key(&challenge.device.public_key));
            assert!(!crypto.verify_proof(&challenge, &forged));
        }
    }

    #[test]
    fn noncanonical_scalar_and_r_encodings_are_rejected() {
        let (crypto, challenge, pair) = material();
        let original: [u8; 64] = pair
            .sign(&challenge.signing_bytes())
            .as_ref()
            .try_into()
            .unwrap();
        // S+L has the same group equation, but is not a canonical Ed25519 scalar.
        let order: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut scalar = original;
        let mut carry = 0_u16;
        for (byte, order) in scalar[32..].iter_mut().zip(order) {
            let sum = u16::from(*byte) + u16::from(order) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        assert!(!crypto.verify_proof(&challenge, &scalar));
        let mut r = original;
        r[..32].fill(0xff);
        r[0] = 0xee;
        r[31] = 0x7f;
        assert!(!crypto.verify_proof(&challenge, &r));
    }
}
