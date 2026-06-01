//! Embedded SPA assets.
//!
//! `hub/static/` is baked into the binary at compile time via
//! `rust-embed`. The directory is also re-read from disk on every
//! request in **debug** builds, so iterating on HTML/CSS/JS doesn't
//! require a recompile. In **release** builds the bytes are static
//! and the entire frontend ships as part of the single `term-hub`
//! binary — no `--static-dir`, no `cp -r`, no drop-ins.
//!
//! `rust-embed`'s `mime-guess` feature populates `data.mimetype()`
//! from the file extension, which we forward as `Content-Type`.

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

pub async fn handler(uri: Uri) -> Response {
    let raw = uri.path().trim_start_matches('/');
    // Root → index.html. Anything ending in a slash isn't a real file;
    // map it to index.html in that directory so the SPA loads.
    let candidate: String = if raw.is_empty() || raw.ends_with('/') {
        format!("{raw}index.html")
    } else {
        raw.to_owned()
    };

    if let Some(file) = Assets::get(&candidate) {
        let mime = file.metadata.mimetype();
        return (
            [(header::CONTENT_TYPE, mime)],
            file.data.into_owned(),
        )
            .into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}
