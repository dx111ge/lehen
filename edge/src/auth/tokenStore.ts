// Bridge to the Rust-side keyring commands defined in src-tauri/src/tokens.rs.
//
// Tokens never live in the webview's localStorage / sessionStorage / IndexedDB
// — the Tauri webview is sandboxed but is also the largest attack surface in
// a desktop app, so secrets stay on the Rust side and are read on demand.

import { invoke } from "@tauri-apps/api/core";

type TokenScope = "hub_login";

export async function storeToken(
  scope: TokenScope,
  token: string,
): Promise<void> {
  await invoke("store_token", { scope, token });
}

export async function getToken(scope: TokenScope): Promise<string | null> {
  return await invoke<string | null>("get_token", { scope });
}

export async function deleteToken(scope: TokenScope): Promise<void> {
  await invoke("delete_token", { scope });
}
