//! Lehen Edge — Tauri v2 application core.
//!
//! Responsibilities split into three modules:
//!
//! * Token storage via the OS Credential Manager (Windows) / Keychain
//!   (macOS) / Secret Service (Linux), exposed to the frontend through
//!   `tauri::command` IPC handlers. The frontend never sees the raw token
//!   on disk; it requests it on demand.
//! * Deep-link emission: the `lehen://` scheme is registered via
//!   `tauri-plugin-deep-link`. Incoming URLs are forwarded to the frontend
//!   as a Tauri event so React can route by path
//!   (`lehen://auth/callback` for Hub-login, `lehen://oauth/callback` for
//!   source-OAuth).
//! * Hub URL configuration: read from environment at startup, exposed to
//!   the frontend on demand. Customers ship pre-configured installers; dev
//!   uses `LEHEN_HUB_URL`.

use std::env;

use serde::{Deserialize, Serialize};
use tauri::Emitter;
use tauri_plugin_deep_link::DeepLinkExt;

mod tokens;

const HUB_URL_ENV_VAR: &str = "LEHEN_HUB_URL";
const DEFAULT_HUB_URL: &str = "http://localhost:8000";

/// Event the Rust side emits when an inbound `lehen://...` URL arrives.
/// The frontend listens on this channel to route to the right handler
/// (Hub-login callback, source-OAuth callback).
const DEEP_LINK_EVENT: &str = "lehen://deep-link";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeepLinkPayload {
    url: String,
}

/// Read-only Hub configuration the frontend asks for at startup.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EdgeConfig {
    hub_url: String,
    /// The deep-link path-prefix Edge uses for Hub-login OIDC callbacks.
    auth_callback_path: String,
    /// The deep-link path-prefix Edge uses for source-adapter OAuth callbacks.
    oauth_callback_path: String,
}

#[tauri::command]
fn get_edge_config() -> EdgeConfig {
    EdgeConfig {
        hub_url: env::var(HUB_URL_ENV_VAR)
            .unwrap_or_else(|_| DEFAULT_HUB_URL.to_string()),
        auth_callback_path: "/auth/callback".to_string(),
        oauth_callback_path: "/oauth/callback".to_string(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_deep_link::init())
        .invoke_handler(tauri::generate_handler![
            get_edge_config,
            tokens::store_token,
            tokens::get_token,
            tokens::delete_token,
        ])
        .setup(|app| {
            // Forward any incoming deep-link URL to the frontend as a Tauri
            // event. The frontend parses the URL and dispatches based on
            // the path (auth/callback vs. oauth/callback). Using the
            // typed plugin API rather than raw event listening keeps the
            // payload schema explicit.
            let app_handle = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                for url in event.urls() {
                    let _ = app_handle.emit(
                        DEEP_LINK_EVENT,
                        DeepLinkPayload {
                            url: url.to_string(),
                        },
                    );
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Lehen Edge");
}
