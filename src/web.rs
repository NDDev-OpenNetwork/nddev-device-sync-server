//! Immutable, manifest-verified browser assets. No directory listing, arbitrary
//! file serving, API fallback or runtime configuration/secret injection.
use crate::AppState;
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    io::Read,
    path::{Component, Path as FilePath},
    sync::Arc,
};

const MAX_ASSET: usize = 64 * 1024 * 1024;
const MAX_TOTAL: usize = 128 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u8,
    files: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    sha256: String,
    bytes: usize,
}
struct Asset {
    bytes: Bytes,
    content_type: &'static str,
    etag: HeaderValue,
}
pub struct WebAssets {
    files: BTreeMap<String, Asset>,
    total: usize,
}
impl fmt::Debug for WebAssets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebAssets")
            .field("files", &self.files.len())
            .field("bytes", &self.total)
            .finish()
    }
}
#[derive(Debug, thiserror::Error)]
#[error("invalid_web_artifact")]
pub struct Error;

fn read(path: &FilePath, limit: usize) -> Result<Vec<u8>, Error> {
    if !std::fs::symlink_metadata(path)
        .map_err(|_| Error)?
        .file_type()
        .is_file()
    {
        return Err(Error);
    }
    let file = File::open(path).map_err(|_| Error)?;
    if file.metadata().map_err(|_| Error)?.len() > limit as u64 {
        return Err(Error);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error)?;
    if bytes.len() > limit {
        return Err(Error);
    }
    Ok(bytes)
}
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.contains('\\')
        && FilePath::new(path)
            .components()
            .all(|p| matches!(p, Component::Normal(_)))
        && !path.split('/').any(|p| p.starts_with('.') || p.is_empty())
}
fn content_type(path: &str) -> Result<&'static str, Error> {
    Ok(match path.rsplit('.').next().unwrap_or_default() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "json" => "application/json",
        "wasm" => "application/wasm",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "svg" => "image/svg+xml",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "bin" | "dat" | "frag" | "vert" | "glsl" => "application/octet-stream",
        _ if path.ends_with("/NOTICES") || path == "NOTICES" => "application/octet-stream",
        _ => return Err(Error),
    })
}
impl WebAssets {
    pub fn load(root: &FilePath) -> Result<Arc<Self>, Error> {
        if !root.is_absolute() {
            return Err(Error);
        }
        let root = std::fs::canonicalize(root).map_err(|_| Error)?;
        let manifest: Manifest =
            serde_json::from_slice(&read(&root.join("nds-assets.json"), 1024 * 1024)?)
                .map_err(|_| Error)?;
        if manifest.schema_version != 1 || manifest.files.is_empty() || manifest.files.len() > 4096
        {
            return Err(Error);
        }
        let mut files = BTreeMap::new();
        let mut total = 0usize;
        for entry in manifest.files {
            if !safe_path(&entry.path) || entry.path == "nds-assets.json" || entry.bytes > MAX_ASSET
            {
                return Err(Error);
            }
            let resolved = std::fs::canonicalize(root.join(&entry.path)).map_err(|_| Error)?;
            if !resolved.starts_with(&root) {
                return Err(Error);
            }
            let bytes = read(&root.join(&entry.path), entry.bytes)?;
            if bytes.len() != entry.bytes {
                return Err(Error);
            }
            total = total
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_TOTAL)
                .ok_or(Error)?;
            let digest = ring::digest::digest(&ring::digest::SHA256, &bytes)
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if entry.sha256 != digest {
                return Err(Error);
            }
            let etag = HeaderValue::from_str(&format!("\"{digest}\"")).map_err(|_| Error)?;
            let kind = content_type(&entry.path)?;
            if files
                .insert(
                    entry.path,
                    Asset {
                        bytes: bytes.into(),
                        content_type: kind,
                        etag,
                    },
                )
                .is_some()
            {
                return Err(Error);
            }
        }
        if !files.contains_key("index.html") {
            return Err(Error);
        }
        Ok(Arc::new(Self { files, total }))
    }
    fn response(&self, path: &str) -> Response {
        let Some(asset) = self.files.get(path) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let mut response = Body::from(asset.bytes.clone()).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(asset.content_type),
        );
        response
            .headers_mut()
            .insert(header::ETAG, asset.etag.clone());
        response
    }
}
fn serve(state: AppState, path: &str) -> Response {
    let mut response = match state.config.web_assets {
        Some(assets) if safe_path(path) => assets.response(path),
        _ => StatusCode::NOT_FOUND.into_response(),
    };
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; manifest-src 'self'; form-action 'self'",
        ),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "same-origin"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-resource-policy", "same-origin"),
        ("x-frame-options", "DENY"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}
pub async fn index(State(state): State<AppState>) -> Response {
    serve(state, "index.html")
}
pub async fn asset(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    if path.starts_with("v1/") || path.starts_with("v2/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve(state, &path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_manifested_regular_assets_with_exact_content_are_served() {
        let root = std::env::temp_dir().join(format!("nds-owned-assets-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let bytes = b"<!doctype html><title>Owned acceptance</title>";
        std::fs::write(root.join("index.html"), bytes).unwrap();
        std::fs::write(root.join("private.txt"), b"SYNTHETIC_NOT_A_WEB_ASSET").unwrap();
        let digest = ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        std::fs::write(root.join("nds-assets.json"),serde_json::to_vec(&serde_json::json!({"schema_version":1,"files":[{"path":"index.html","sha256":digest,"bytes":bytes.len()}]})).unwrap()).unwrap();
        let assets = WebAssets::load(&root).unwrap();
        assert_eq!(assets.response("index.html").status(), StatusCode::OK);
        assert_eq!(
            assets.response("private.txt").status(),
            StatusCode::NOT_FOUND
        );
        std::fs::write(root.join("index.html"), b"changed").unwrap();
        assert!(WebAssets::load(&root).is_err());
        for path in [
            "../index.html",
            "/index.html",
            ".env",
            "a/../index.html",
            "a\\file",
            "a//file",
        ] {
            assert!(!safe_path(path));
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
