// Deep-link routing.
//
// The Rust side emits a Tauri event ``lehen://deep-link`` whenever an
// inbound ``lehen://...`` URL arrives. The frontend subscribes here and
// dispatches based on the path — the Edge owns two callback paths:
//
//   * ``lehen:/auth/callback`` — Hub-login OIDC response. Edge does the
//     token exchange itself (PKCE) and stores the resulting access token.
//   * ``lehen:/oauth/callback`` — source-adapter OAuth response (Sprint 2
//     outlook-graph and beyond). Edge forwards ``code`` + ``state`` to the
//     Hub's ``/me/connections/{id}/complete`` endpoint.

import { listen, type UnlistenFn } from "@tauri-apps/api/event";

interface DeepLinkPayload {
  url: string;
}

export interface DeepLinkParams {
  path: string;
  query: URLSearchParams;
}

export async function subscribeDeepLinks(
  onAuth: (params: DeepLinkParams) => void,
  onOauth: (params: DeepLinkParams) => void,
): Promise<UnlistenFn> {
  return await listen<DeepLinkPayload>("lehen://deep-link", (event) => {
    const url = event.payload.url;
    let parsed: URL;
    try {
      // The lehen:// scheme is parsed by URL just fine in modern browsers.
      parsed = new URL(url);
    } catch {
      return;
    }
    const path = parsed.pathname;
    const params: DeepLinkParams = { path, query: parsed.searchParams };
    if (path.startsWith("/auth/")) {
      onAuth(params);
    } else if (path.startsWith("/oauth/")) {
      onOauth(params);
    }
  });
}
