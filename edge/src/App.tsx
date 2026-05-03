import type { UnlistenFn } from "@tauri-apps/api/event";
import { useCallback, useEffect, useState } from "react";

import { fetchAuthPublicConfig, fetchMe, completeGrant, getEdgeConfig } from "./api/hub";
import type { AuthPublicConfig, MeResponse } from "./api/types";
import { type DeepLinkParams, subscribeDeepLinks } from "./auth/deepLink";
import { completeHubLogin } from "./auth/pkce";
import { deleteToken, getToken, storeToken } from "./auth/tokenStore";
import { Connections } from "./views/Connections";
import { Login } from "./views/Login";

interface BootState {
  hubUrl: string;
  oauthRedirectUri: string;
  publicConfig: AuthPublicConfig;
}

const PROVIDER_LABEL: Record<string, string> = {
  keycloak: "Keycloak",
  entra: "Microsoft Entra",
};

export function App() {
  const [boot, setBoot] = useState<BootState | null>(null);
  const [bearer, setBearer] = useState<string | null>(null);
  const [me, setMe] = useState<MeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingConnectInstance, setPendingConnectInstance] = useState<
    string | null
  >(null);

  // Boot: load Hub config + the active SIAM provider's discovery info.
  useEffect(() => {
    (async () => {
      try {
        const edgeConfig = await getEdgeConfig();
        const publicConfig = await fetchAuthPublicConfig();
        setBoot({
          hubUrl: edgeConfig.hub_url,
          oauthRedirectUri: `lehen:/${edgeConfig.oauth_callback_path}`,
          publicConfig,
        });
        const stored = await getToken("hub_login");
        if (stored) {
          setBearer(stored);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    })();
  }, []);

  const refreshMe = useCallback(async (token: string) => {
    try {
      setMe(await fetchMe(token));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // 401 → token rejected, force re-login.
      if (message.includes("401")) {
        await deleteToken("hub_login");
        setBearer(null);
        setMe(null);
        setError("Session expired — please sign in again.");
      } else {
        setError(message);
      }
    }
  }, []);

  // Refresh /me whenever the bearer changes.
  useEffect(() => {
    if (bearer) {
      void refreshMe(bearer);
    }
  }, [bearer, refreshMe]);

  // Subscribe to deep-link callbacks.
  useEffect(() => {
    let unsub: UnlistenFn | null = null;
    (async () => {
      unsub = await subscribeDeepLinks(
        async (params: DeepLinkParams) => {
          // Hub-login callback → exchange code for access token, store, set bearer.
          const code = params.query.get("code");
          const state = params.query.get("state");
          if (!code || !state) {
            setError("auth callback missing code or state");
            return;
          }
          try {
            const { accessToken } = await completeHubLogin(state, code);
            await storeToken("hub_login", accessToken);
            setBearer(accessToken);
            setError(null);
          } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
          }
        },
        async (params: DeepLinkParams) => {
          // Source-OAuth callback → forward to Hub's /complete endpoint.
          const code = params.query.get("code");
          const state = params.query.get("state");
          if (!code || !state || !bearer) {
            setError("oauth callback missing code, state, or active session");
            return;
          }
          if (!pendingConnectInstance) {
            setError(
              "oauth callback received but no pending connect instance — refusing",
            );
            return;
          }
          try {
            await completeGrant(bearer, pendingConnectInstance, code, state);
            setPendingConnectInstance(null);
            await refreshMe(bearer);
          } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
          }
        },
      );
    })();
    return () => {
      if (unsub) {
        unsub();
      }
    };
  }, [bearer, pendingConnectInstance, refreshMe]);

  const handleSignOut = useCallback(async () => {
    await deleteToken("hub_login");
    setBearer(null);
    setMe(null);
  }, []);

  return (
    <div className="app-shell">
      <header className="app-header">
        <h1>Lehen Edge</h1>
        {bearer && <button onClick={handleSignOut}>Sign out</button>}
      </header>
      {error && <div className="error">{error}</div>}
      {!boot ? (
        <p>Connecting to Hub…</p>
      ) : !bearer ? (
        <Login
          hubUrl={boot.hubUrl}
          providerLabel={
            PROVIDER_LABEL[boot.publicConfig.provider] ?? boot.publicConfig.provider
          }
          onError={setError}
        />
      ) : !me ? (
        <p>Loading your integrations…</p>
      ) : (
        <Connections
          me={me}
          bearer={bearer}
          redirectUri={boot.oauthRedirectUri}
          onConnectStarted={setPendingConnectInstance}
          onError={setError}
        />
      )}
    </div>
  );
}
