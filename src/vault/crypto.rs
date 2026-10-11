use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nddev_device_sync_application::{
    identity::Owner,
    vault::{KeyMaterial, SyncError},
};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};
use zeroize::Zeroizing;

pub struct WrappingKey(aead::LessSafeKey);

impl std::fmt::Debug for WrappingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WrappingKey([REDACTED])")
    }
}

impl WrappingKey {
    pub fn read(path: &str) -> Result<Self, crate::config::ConfigError> {
        use std::os::unix::fs::PermissionsExt;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| crate::config::ConfigError::VaultKey)?;
        let metadata = file
            .metadata()
            .map_err(|_| crate::config::ConfigError::VaultKey)?;
        if !metadata.is_file() || metadata.len() > 128 || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(crate::config::ConfigError::VaultKey);
        }
        let mut text = Zeroizing::new(String::new());
        file.take(128)
            .read_to_string(&mut text)
            .map_err(|_| crate::config::ConfigError::VaultKey)?;
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(text.trim())
                .map_err(|_| crate::config::ConfigError::VaultKey)?,
        );
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(bytes.as_slice()) != text.trim() {
            return Err(crate::config::ConfigError::VaultKey);
        }
        Ok(Self(aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, bytes.as_slice())
                .map_err(|_| crate::config::ConfigError::VaultKey)?,
        )))
    }

    pub fn seal(&self, owner: &Owner, key: &KeyMaterial) -> Result<([u8; 12], Vec<u8>), SyncError> {
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SyncError::Unavailable)?;
        let mut bytes = Zeroizing::new(key.expose().to_vec());
        self.0
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad(owner, &key.id())?),
                &mut *bytes,
            )
            .map_err(|_| SyncError::Unavailable)?;
        Ok((nonce, bytes.to_vec())) // Only authenticated ciphertext leaves this adapter.
    }

    pub fn open(
        &self,
        owner: &Owner,
        id: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<KeyMaterial, SyncError> {
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| SyncError::Unavailable)?;
        if ciphertext.len() != 64 {
            return Err(SyncError::Unavailable);
        }
        let mut bytes = Zeroizing::new(ciphertext.to_vec());
        let plain = self
            .0
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad(owner, id)?),
                &mut bytes,
            )
            .map_err(|_| SyncError::Unavailable)?;
        let key = KeyMaterial::new(plain).map_err(|_| SyncError::Unavailable)?;
        if key.id() != id {
            return Err(SyncError::Unavailable);
        }
        Ok(key)
    }
}

fn aad(owner: &Owner, id: &str) -> Result<Vec<u8>, SyncError> {
    serde_json::to_vec(&(
        "NDS-SERVER-OWNER-KEY-V1",
        owner.tenant_id.as_str(),
        owner.user_id.as_str(),
        id,
    ))
    .map_err(|_| SyncError::Unavailable)
}

pub fn generate() -> Result<KeyMaterial, SyncError> {
    let mut bytes = Zeroizing::new([0; 48]);
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    SystemRandom::new()
        .fill(&mut bytes[16..])
        .map_err(|_| SyncError::Unavailable)?;
    KeyMaterial::new(bytes.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nddev_device_sync_application::identity::{TenantId, UserId};
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn actual_key_envelopes_reject_tampering_cross_owner_and_insecure_files() {
        let directory =
            std::env::temp_dir().join(format!("nds-key-check-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        struct Owned(std::path::PathBuf);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _owned = Owned(directory.clone());
        let path = directory.join("wrapping");
        let mut secret = Zeroizing::new([0; 32]);
        SystemRandom::new().fill(secret.as_mut()).unwrap();
        std::fs::write(&path, URL_SAFE_NO_PAD.encode(secret.as_slice())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let wrapping = WrappingKey::read(path.to_str().unwrap()).unwrap();
        let owner = Owner {
            user_id: UserId::new("owner").unwrap(),
            tenant_id: TenantId::new("tenant").unwrap(),
        };
        let key = generate().unwrap();
        let (nonce, mut ciphertext) = wrapping.seal(&owner, &key).unwrap();
        assert_eq!(
            wrapping
                .open(&owner, &key.id(), &nonce, &ciphertext)
                .unwrap()
                .expose(),
            key.expose()
        );
        let other = Owner {
            user_id: UserId::new("other").unwrap(),
            ..owner.clone()
        };
        assert!(
            wrapping
                .open(&other, &key.id(), &nonce, &ciphertext)
                .is_err()
        );
        ciphertext[0] ^= 1;
        assert!(
            wrapping
                .open(&owner, &key.id(), &nonce, &ciphertext)
                .is_err()
        );
        assert!(
            !format!("{wrapping:?} {key:?}").contains(&URL_SAFE_NO_PAD.encode(secret.as_slice()))
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(WrappingKey::read(path.to_str().unwrap()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.join("link");
        symlink(&path, &link).unwrap();
        assert!(WrappingKey::read(link.to_str().unwrap()).is_err());
    }
}
