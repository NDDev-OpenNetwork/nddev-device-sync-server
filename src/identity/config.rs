use super::crypto::Crypto;
use crate::config::{ConfigError, SecretString, read_secret};
use nddev_device_sync_application::identity::EmailAddress;
use serde::Deserialize;
use std::{fmt, net::IpAddr};

#[derive(Clone)]
pub struct AuthConfig {
    pub owner_email: EmailAddress,
    pub crypto: Crypto,
    pub smtp: Option<SmtpConfig>,
    pub github: Option<GithubConfig>,
}
impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthConfig([REDACTED])")
    }
}
#[derive(Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub tls: SmtpTls,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub from: EmailAddress,
}
#[derive(Clone)]
pub struct GithubConfig {
    pub owner_id: u64,
    pub client_id: String,
    pub client_secret: SecretString,
    pub callback: reqwest::Url,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTls {
    Tls,
    Starttls,
    Loopback,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    owner_email: String,
    pepper_file: String,
    smtp: Option<SmtpInput>,
    github: Option<GithubInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SmtpInput {
    host: String,
    port: u16,
    tls: SmtpTls,
    username: Option<String>,
    password_file: Option<String>,
    from: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GithubInput {
    owner_id: u64,
    client_id: String,
    client_secret_file: String,
    callback_url: String,
}

fn file(path: &str) -> Result<SecretString, ConfigError> {
    read_secret(None, Some(path.into()))?.ok_or(ConfigError::Identity)
}

impl AuthConfig {
    pub fn read(path: &str) -> Result<Self, ConfigError> {
        let source = file(path)?;
        let input: Input =
            serde_json::from_str(source.expose()).map_err(|_| ConfigError::Identity)?;
        if input.smtp.is_none() && input.github.is_none() {
            return Err(ConfigError::Identity);
        }
        let owner_email =
            EmailAddress::parse(&input.owner_email).map_err(|_| ConfigError::Identity)?;
        let crypto =
            Crypto::new(file(&input.pepper_file)?.expose()).map_err(|_| ConfigError::Identity)?;
        let smtp = input
            .smtp
            .map(|input| {
                let loopback = input
                    .host
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback());
                if input.host.is_empty()
                    || input.host.len() > 253
                    || input.port == 0
                    || (!loopback
                        && !input
                            .host
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)))
                    || (matches!(input.tls, SmtpTls::Loopback) && !loopback)
                    || input.username.is_some() != input.password_file.is_some()
                    || input.username.as_ref().is_some_and(|value| {
                        value.is_empty()
                            || value.len() > 254
                            || value.bytes().any(|b| b.is_ascii_control())
                    })
                {
                    return Err(ConfigError::Identity);
                }
                Ok(SmtpConfig {
                    host: input.host,
                    port: input.port,
                    tls: input.tls,
                    username: input.username,
                    password: input.password_file.map(|path| file(&path)).transpose()?,
                    from: EmailAddress::parse(&input.from).map_err(|_| ConfigError::Identity)?,
                })
            })
            .transpose()?;
        let github = input
            .github
            .map(|input| {
                let callback =
                    reqwest::Url::parse(&input.callback_url).map_err(|_| ConfigError::Identity)?;
                if input.owner_id == 0
                    || input.owner_id > i64::MAX as u64
                    || input.client_id.is_empty()
                    || input.client_id.len() > 128
                    || !input
                        .client_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    || callback.scheme() != "https"
                    || callback.host_str().is_none()
                    || !callback.username().is_empty()
                    || callback.password().is_some()
                    || callback.query().is_some()
                    || callback.fragment().is_some()
                    || callback.path() != "/v2/auth/github/callback"
                {
                    return Err(ConfigError::Identity);
                }
                Ok(GithubConfig {
                    owner_id: input.owner_id,
                    client_id: input.client_id,
                    client_secret: file(&input.client_secret_file)?,
                    callback,
                })
            })
            .transpose()?;
        Ok(Self {
            owner_email,
            crypto,
            smtp,
            github,
        })
    }
}
