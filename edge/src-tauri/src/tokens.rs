//! OS-credential-store token storage commands.
//!
//! The Edge stores Hub-bound bearer tokens in the platform secret store —
//! Windows Credential Manager, macOS Keychain, or Linux Secret Service —
//! via the `keyring` crate. The frontend asks for tokens on demand; they
//! never live in Tauri's webview-accessible filesystem.
//!
//! ``service`` namespacing keeps Hub-login tokens separate from any future
//! source-OAuth tokens that the Edge might cache locally (Sprint 3+).

use keyring::Entry;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SERVICE_NAME: &str = "lehen-edge";

#[derive(Debug, Error)]
pub enum TokenStoreError {
    #[error("keyring error: {0}")]
    Keyring(#[from] keyring::Error),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenScope {
    /// Bearer token issued by the SIAM IdP for Hub authentication.
    HubLogin,
}

impl TokenScope {
    fn account_key(&self) -> &'static str {
        match self {
            TokenScope::HubLogin => "hub-login",
        }
    }
}

fn entry_for(scope: &TokenScope) -> Result<Entry, TokenStoreError> {
    Entry::new(SERVICE_NAME, scope.account_key()).map_err(Into::into)
}

#[tauri::command]
pub fn store_token(scope: TokenScope, token: String) -> Result<(), String> {
    entry_for(&scope)
        .and_then(|e| e.set_password(&token).map_err(Into::into))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_token(scope: TokenScope) -> Result<Option<String>, String> {
    let entry = entry_for(&scope).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(token) => Ok(Some(token)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
pub fn delete_token(scope: TokenScope) -> Result<(), String> {
    let entry = entry_for(&scope).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
