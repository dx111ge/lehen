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

use std::collections::HashMap;
use std::env;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tauri_plugin_deep_link::DeepLinkExt;
use tauri_plugin_http::reqwest;

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

#[derive(Debug, Serialize, Deserialize)]
struct OidcTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    token_type: Option<String>,
    scope: Option<String>,
}

/// OIDC PKCE code exchange.
///
/// Done in Rust (not from the webview) because Microsoft's v2 token endpoint
/// rejects "Mobile and desktop applications" client-type tokens redeemed
/// from a webview origin (AADSTS9002326). reqwest from Rust sends no Origin
/// header, so Microsoft sees the request as a native client — which is what
/// the app is registered as.
#[tauri::command]
async fn exchange_oidc_code(
    token_endpoint: String,
    client_id: String,
    redirect_uri: String,
    code: String,
    code_verifier: String,
) -> Result<OidcTokenResponse, String> {
    let mut form: HashMap<&str, String> = HashMap::new();
    form.insert("grant_type", "authorization_code".to_string());
    form.insert("client_id", client_id);
    form.insert("redirect_uri", redirect_uri);
    form.insert("code", code);
    form.insert("code_verifier", code_verifier);

    let resp = reqwest::Client::new()
        .post(&token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("token endpoint unreachable: {e}"))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("token endpoint body read failed: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "token endpoint returned {status}: {}",
            body.chars().take(500).collect::<String>()
        ));
    }
    serde_json::from_str::<OidcTokenResponse>(&body)
        .map_err(|e| format!("token endpoint response not parseable as OIDC tokens: {e}"))
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
        // single-instance MUST be registered first. With the ``deep-link``
        // feature enabled, it forwards any deep-link URL passed to the
        // second invocation back to the running instance via the deep-link
        // plugin's on_open_url callback. Without this, every callback
        // ``lehen://...`` from the system browser spawns a NEW Edge process
        // instead of waking the one the user is already signed into.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_deep_link::init())
        .invoke_handler(tauri::generate_handler![
            get_edge_config,
            exchange_oidc_code,
            tokens::store_token,
            tokens::get_token,
            tokens::delete_token,
        ])
        .setup(|app| {
            // Register the ``lehen://`` scheme with the OS at runtime. On
            // production builds the MSI installer handles this via the
            // bundle manifest; in ``tauri dev`` we have to do it ourselves
            // or every callback fails with "scheme has no registered
            // handler". macOS handles the scheme via Info.plist so the
            // call is a no-op there; Windows + Linux need this.
            #[cfg(any(windows, target_os = "linux"))]
            {
                if let Err(e) = app.deep_link().register_all() {
                    eprintln!("warning: deep-link scheme registration failed: {e}");
                }
            }

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
