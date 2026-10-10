pub mod config;
pub(crate) mod crypto;
mod email;
mod flows;
mod github;
pub mod http;
pub(crate) mod store;

use config::AuthConfig;
use nddev_device_sync_application::identity::{
    IdentityBinding, IdentityCrypto, IdentityError, IdentityService,
};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
pub type Service =
    IdentityService<store::Store, crypto::Crypto, email::Mailer, github::Github, flows::Flows>;

pub fn now_ms() -> Result<u64, IdentityError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IdentityError::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| IdentityError::Unavailable)
}

pub async fn initialize(
    pool: sqlx::PgPool,
    config: &AuthConfig,
) -> Result<Arc<Service>, IdentityError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let store = store::Store::new(pool);
    let github_id = config.github.as_ref().map(|github| github.owner_id);
    let owner = store
        .bootstrap(
            config
                .crypto
                .protect("owner_binding", &[config.owner_email.as_str().as_bytes()]),
            github_id,
        )
        .await?;
    let email = email::Mailer::new(config.smtp.as_ref(), store.clone()).await?;
    let github = github::Github::new(config.github.as_ref()).await?;
    let service = IdentityService::new(
        store,
        config.crypto.clone(),
        email,
        github,
        flows::Flows::default(),
        IdentityBinding {
            owner,
            email: config.owner_email.clone(),
            github_id,
        },
    );
    let methods = service.methods();
    tracing::info!(
        event.name = "identity.initialized",
        email_available = methods.0,
        github_available = methods.1,
        outcome = "ready"
    );
    Ok(Arc::new(service))
}
