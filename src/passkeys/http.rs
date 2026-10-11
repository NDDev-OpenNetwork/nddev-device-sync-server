use super::{Exchange, Service};
use crate::{
    AppState,
    admission::PeerAddress,
    identity::{
        self,
        http::{ApiError, bearer},
    },
    protocol_v2 as dto,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Query, State},
    http::{HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use nddev_device_sync_application::identity::{
    IdentityCrypto, IdentityError, IdentityStore, POLL_RATE, START_RATE,
};
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v2/auth/passkeys/start", post(start))
        .route("/v2/auth/passkeys/exchange", post(exchange))
        .route("/v2/auth/passkeys/browser", get(browser))
        .route("/v2/auth/passkeys/options", get(options))
        .route(
            "/v2/auth/passkeys/verify",
            post(verify).layer(DefaultBodyLimit::max(16_384)),
        )
}
fn service(state: &AppState) -> Result<&Service, IdentityError> {
    state.passkeys.as_deref().ok_or(IdentityError::Unavailable)
}
async fn limit(
    state: &AppState,
    source: &PeerAddress,
    action: &'static str,
    policy: nddev_device_sync_application::identity::RatePolicy,
    now: u64,
) -> Result<(), IdentityError> {
    let crypto = &state
        .config
        .identity
        .as_ref()
        .ok_or(IdentityError::Unavailable)?
        .crypto;
    let key = crypto.protect(action, &[source.0.to_string().as_bytes()]);
    crate::identity::store::Store::new(state.database.clone().ok_or(IdentityError::Unavailable)?)
        .admit_source(key, policy, now)
        .await
}
async fn start(
    State(state): State<AppState>,
    Extension(source): Extension<PeerAddress>,
    headers: HeaderMap,
    Json(input): Json<dto::PasskeyRequest>,
) -> Result<Json<dto::PasskeyStart>, ApiError> {
    let now = identity::now_ms()?;
    limit(&state, &source, "passkey_start", START_RATE, now).await?;
    let auth = if input.registration {
        Some(
            state
                .identity
                .as_ref()
                .ok_or(IdentityError::Unavailable)?
                .authenticate(bearer(&headers)?, now)
                .await?,
        )
    } else {
        None
    };
    let result = service(&state)?.start(auth, now).await?;
    tracing::info!(
        module = "identity",
        scope = "http",
        event.name = "identity.passkey.started",
        outcome = "pending"
    );
    Ok(Json(result))
}
async fn exchange(
    State(state): State<AppState>,
    Extension(source): Extension<PeerAddress>,
    Json(input): Json<dto::GithubExchangeRequest>,
) -> Result<Response, ApiError> {
    let now = identity::now_ms()?;
    limit(&state, &source, "passkey_poll", POLL_RATE, now).await?;
    Ok(
        match service(&state)?
            .exchange(&input.flow_id, &input.exchange_token, now)
            .await?
        {
            Exchange::Pending => (
                axum::http::StatusCode::ACCEPTED,
                Json(dto::PasskeyStatus {
                    status: dto::PasskeyStatusStatus::Pending,
                    retry_after_seconds: 2,
                }),
            )
                .into_response(),
            Exchange::Registered => Json(dto::PasskeyStatus {
                status: dto::PasskeyStatusStatus::Registered,
                retry_after_seconds: 0,
            })
            .into_response(),
            Exchange::Session(session) => identity::http::issued(session)?.into_response(),
        },
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Id {
    flow_id: String,
}
fn proof(headers: &HeaderMap) -> Result<(&str, &str), IdentityError> {
    if headers.get_all("cookie").iter().count() != 1
        || headers.get_all("x-nds-csrf").iter().count() != 1
    {
        return Err(IdentityError::Denied);
    }
    let cookie = headers
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(';')
                .map(str::trim)
                .filter_map(|part| part.strip_prefix("nds_passkey="))
                .collect::<Vec<_>>()
                .as_slice()
                .first()
                .copied()
                .filter(|_| {
                    value
                        .split(';')
                        .filter(|part| part.trim().starts_with("nds_passkey="))
                        .count()
                        == 1
                })
        })
        .ok_or(IdentityError::Denied)?;
    let csrf = headers
        .get("x-nds-csrf")
        .and_then(|value| value.to_str().ok())
        .ok_or(IdentityError::Denied)?;
    if cookie.len() != 43 || csrf.len() != 43 {
        return Err(IdentityError::Denied);
    }
    Ok((cookie, csrf))
}
async fn options(
    State(state): State<AppState>,
    Query(id): Query<Id>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (cookie, csrf) = proof(&headers)?;
    Ok(Json(service(&state)?.options(&id.flow_id, cookie, csrf)?))
}
async fn verify(
    State(state): State<AppState>,
    Query(id): Query<Id>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if headers.get_all("origin").iter().count() != 1 {
        return Err(IdentityError::Denied.into());
    }
    let origin = headers
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .ok_or(IdentityError::Denied)?;
    if origin != service(&state)?.origin.origin().ascii_serialization() {
        return Err(IdentityError::Denied.into());
    }
    let (cookie, csrf) = proof(&headers)?;
    service(&state)?
        .finish(&id.flow_id, cookie, csrf, value, identity::now_ms()?)
        .await?;
    tracing::info!(
        module = "identity",
        scope = "http",
        event.name = "identity.passkey.verified",
        outcome = "ok"
    );
    Ok(Json(serde_json::json!({"status":"verified"})))
}
async fn browser(
    State(state): State<AppState>,
    Query(id): Query<Id>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let service = service(&state)?;
    let previous_cookie = headers
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(';')
                .map(str::trim)
                .find_map(|part| part.strip_prefix("nds_passkey="))
        });
    let duplicate = headers
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .filter(|part| part.trim().starts_with("nds_passkey="))
                .count()
                > 1
        });
    if duplicate
        || headers.get_all("cookie").iter().count() > 1
        || previous_cookie.is_some_and(|cookie| cookie.len() != 43)
    {
        return Err(IdentityError::Denied.into());
    }
    let (cookie, csrf, code, registration) = service.browser(&id.flow_id, previous_cookie)?;
    let russian = headers
        .get("accept-language")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("ru"));
    let title = if russian {
        "Ключ доступа NDS"
    } else {
        "NDS passkey"
    };
    let instruction = if russian {
        "Сравните код с приложением NDS и продолжайте только при совпадении."
    } else {
        "Compare this code with the NDS application and continue only when it matches."
    };
    let action = if registration {
        if russian {
            "Создать ключ доступа"
        } else {
            "Create passkey"
        }
    } else if russian {
        "Войти с ключом доступа"
    } else {
        "Sign in with passkey"
    };
    let settings =
        serde_json::json!({"id":id.flow_id,"csrf":csrf,"registration":registration}).to_string();
    let nonce = state
        .config
        .identity
        .as_ref()
        .ok_or(IdentityError::Unavailable)?
        .crypto
        .token()?
        .into_inner();
    let body = format!(
        "<!doctype html><html lang=\"{}\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>{title}</title><body><h1>NDDev OpenNetwork · {title}</h1><p>{instruction}</p><p><strong>{code}</strong></p><button id=\"continue\">{action}</button><p id=\"result\" role=\"status\"></p><a href=\"https://nddev.ai\">nddev.ai</a><script nonce=\"{nonce}\">const settings={settings};{}</script></body></html>",
        if russian { "ru" } else { "en" },
        include_str!("browser.js")
    );
    let mut response = Html(body).into_response();
    response.headers_mut().insert("content-security-policy",HeaderValue::from_str(&format!("default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")).map_err(|_|IdentityError::Unavailable)?);
    let secure = if service.origin.scheme() == "https" {
        "; Secure"
    } else {
        ""
    };
    response.headers_mut().insert("set-cookie",HeaderValue::from_str(&format!("nds_passkey={cookie}; Path=/v2/auth/passkeys; HttpOnly; SameSite=Strict; Max-Age=300{secure}")).map_err(|_|IdentityError::Unavailable)?);
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    Ok(response)
}
