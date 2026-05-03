// OIDC Authorization Code with PKCE (RFC 7636) for Hub login.
//
// The Edge does the dance itself rather than relying on a library because
// the Tauri runtime model — system browser for IdP redirect, deep-link
// callback into the Edge — doesn't fit the typical browser-only flows
// the popular OIDC libraries assume. The flow is:
//
//   1. Fetch the IdP's well-known config (from the Hub's /auth/public-config).
//   2. Generate code_verifier + code_challenge.
//   3. Open the authorization URL in the system browser via plugin-shell.
//   4. Listen on the deep-link channel for ``lehen://auth/callback?code=...``.
//   5. Exchange code for tokens at the token_endpoint.
//   6. Hand the access_token to the keyring (via `tokens::store_token`).

import { invoke } from "@tauri-apps/api/core";
import { fetch } from "@tauri-apps/plugin-http";
import { open as openExternal } from "@tauri-apps/plugin-shell";

import { fetchAuthPublicConfig, getEdgeConfig } from "../api/hub";
import type { AuthPublicConfig, OidcDiscovery } from "../api/types";

interface OidcTokenResponse {
  access_token: string;
  refresh_token: string | null;
  expires_in: number | null;
  token_type: string | null;
  scope: string | null;
}

interface AuthorizationContext {
  state: string;
  codeVerifier: string;
  publicConfig: AuthPublicConfig;
  discovery: OidcDiscovery;
  redirectUri: string;
}

// Pending flow contexts persist in ``sessionStorage`` rather than a
// module-level Map. Vite HMR re-executes a module when that module's
// source changes, which would clear an in-memory Map mid-flow. The
// session store survives HMR (and page reloads within the same window),
// so the user's authorization round-trip can take as long as Microsoft's
// login UX requires without us losing the verifier.

const FLOW_KEY_PREFIX = "lehen_pkce_flow_";

function flowKey(state: string): string {
  return `${FLOW_KEY_PREFIX}${state}`;
}

function storeFlow(ctx: AuthorizationContext): void {
  sessionStorage.setItem(flowKey(ctx.state), JSON.stringify(ctx));
}

function takeFlow(state: string): AuthorizationContext | null {
  const raw = sessionStorage.getItem(flowKey(state));
  if (!raw) return null;
  sessionStorage.removeItem(flowKey(state));
  try {
    return JSON.parse(raw) as AuthorizationContext;
  } catch {
    return null;
  }
}

function randomString(byteLen: number): string {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return base64UrlNoPad(bytes);
}

function base64UrlNoPad(bytes: Uint8Array): string {
  // btoa wants a binary string; build one without using string concatenation
  // pitfalls on large buffers.
  let bin = "";
  for (const byte of bytes) {
    bin += String.fromCharCode(byte);
  }
  return btoa(bin)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sha256(input: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

async function fetchDiscovery(wellKnownUrl: string): Promise<OidcDiscovery> {
  const response = await fetch(wellKnownUrl, {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(
      `OIDC discovery failed: ${response.status} ${response.statusText}`,
    );
  }
  return (await response.json()) as OidcDiscovery;
}

/**
 * Begin a Hub-login flow. Generates PKCE, registers a pending flow, opens
 * the authorization URL in the system browser. Returns when the browser
 * has been opened — the actual completion happens via the deep-link event.
 */
export async function beginHubLogin(): Promise<{ state: string }> {
  const publicConfig = await fetchAuthPublicConfig();
  const discovery = await fetchDiscovery(publicConfig.well_known_url);
  const edgeConfig = await getEdgeConfig();
  const redirectUri = `lehen:/${edgeConfig.auth_callback_path}`;

  const codeVerifier = randomString(32);
  const challengeBytes = await sha256(codeVerifier);
  const codeChallenge = base64UrlNoPad(challengeBytes);
  const state = randomString(16);

  storeFlow({
    state,
    codeVerifier,
    publicConfig,
    discovery,
    redirectUri,
  });

  // OAuth-2 wants ONE ``scope`` param with space-separated values; calling
  // ``params.append("scope", ...)`` after the constructor creates a second
  // ``scope`` query parameter, which Entra rejects with AADSTS9000411.
  // Build the full scope list first, then put it in the URLSearchParams.
  // ``offline_access`` is required for Entra to issue a refresh token.
  // The API scope (``${audience}/access_as_user``) is what makes the
  // resulting access token's ``aud`` match the Hub's expected audience.
  const scopes = ["openid", "profile", "email", "offline_access"];
  if (publicConfig.audience) {
    scopes.push(`${publicConfig.audience}/access_as_user`);
  }
  const params = new URLSearchParams({
    client_id: publicConfig.edge_client_id,
    response_type: "code",
    redirect_uri: redirectUri,
    scope: scopes.join(" "),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  const authUrl = `${discovery.authorization_endpoint}?${params.toString()}`;
  await openExternal(authUrl);
  return { state };
}

/**
 * Exchange the authorization code received via the deep-link callback for
 * tokens. Returns the raw access token; persistence to the keyring is the
 * caller's responsibility (so it can also store any companion state).
 */
export async function completeHubLogin(
  state: string,
  code: string,
): Promise<{ accessToken: string; expiresIn: number }> {
  const context = takeFlow(state);
  if (!context) {
    throw new Error(
      "no pending flow matches the returned state — possible replay or restart",
    );
  }

  // Token exchange goes through a Rust command rather than fetch — Microsoft
  // rejects the redemption with AADSTS9002326 if the request carries a
  // webview Origin header (the app is registered as native, not SPA).
  // reqwest from Rust sends no Origin header, so Microsoft treats the
  // request correctly as a native-client redemption.
  const data = await invoke<OidcTokenResponse>("exchange_oidc_code", {
    tokenEndpoint: context.discovery.token_endpoint,
    clientId: context.publicConfig.edge_client_id,
    redirectUri: context.redirectUri,
    code,
    codeVerifier: context.codeVerifier,
  });
  return {
    accessToken: data.access_token,
    expiresIn: data.expires_in ?? 3600,
  };
}

/**
 * Abandon any in-flight Hub-login flow. Used on logout or restart so a
 * stale state can't be replayed.
 */
export function clearPendingFlows(): void {
  for (let i = sessionStorage.length - 1; i >= 0; i -= 1) {
    const key = sessionStorage.key(i);
    if (key && key.startsWith(FLOW_KEY_PREFIX)) {
      sessionStorage.removeItem(key);
    }
  }
}
