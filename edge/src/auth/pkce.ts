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

import { open as openExternal } from "@tauri-apps/plugin-shell";

import { fetchAuthPublicConfig, getEdgeConfig } from "../api/hub";
import type { AuthPublicConfig, OidcDiscovery } from "../api/types";

interface AuthorizationContext {
  state: string;
  codeVerifier: string;
  publicConfig: AuthPublicConfig;
  discovery: OidcDiscovery;
  redirectUri: string;
}

// In-memory map of state → context. The Edge process is single-user so a
// module-level map is fine; if the user starts a flow and never completes it
// the entry leaks until the next restart, which is acceptable.
const pendingFlows = new Map<string, AuthorizationContext>();

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

  pendingFlows.set(state, {
    state,
    codeVerifier,
    publicConfig,
    discovery,
    redirectUri,
  });

  const params = new URLSearchParams({
    client_id: publicConfig.edge_client_id,
    response_type: "code",
    redirect_uri: redirectUri,
    scope: "openid profile email",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  if (publicConfig.audience) {
    // Some Entra app registrations require explicit audience as a scope to
    // get a token for the Hub-API resource. Pass it as the resource scope.
    params.append("scope", `${publicConfig.audience}/.default`);
  }

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
  const context = pendingFlows.get(state);
  if (!context) {
    throw new Error(
      "no pending flow matches the returned state — possible replay or restart",
    );
  }
  pendingFlows.delete(state);

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: context.publicConfig.edge_client_id,
    code,
    redirect_uri: context.redirectUri,
    code_verifier: context.codeVerifier,
  });
  const response = await fetch(context.discovery.token_endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: body.toString(),
  });
  if (!response.ok) {
    throw new Error(
      `token exchange failed: ${response.status} ${await response.text()}`,
    );
  }
  const data = (await response.json()) as {
    access_token: string;
    expires_in?: number;
  };
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
  pendingFlows.clear();
}
