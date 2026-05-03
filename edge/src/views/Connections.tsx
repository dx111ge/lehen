import { open as openExternal } from "@tauri-apps/plugin-shell";
import { useState } from "react";

import { initiateGrant } from "../api/hub";
import type { MeResponse, MeIntegration } from "../api/types";

interface ConnectionsProps {
  me: MeResponse;
  bearer: string;
  redirectUri: string;
  onConnectStarted: (instanceId: string) => void;
  onError: (message: string) => void;
}

/**
 * Lists the user's authorized integration instances and their connection
 * status. The Connect button starts an OAuth flow against the source IdP
 * by calling the Hub's ``/initiate`` endpoint and opening the returned
 * auth URL in the system browser. Completion is handled by the deep-link
 * subscription in App.
 */
export function Connections({
  me,
  bearer,
  redirectUri,
  onConnectStarted,
  onError,
}: ConnectionsProps) {
  return (
    <section>
      <header>
        <p>
          Signed in as <strong>{me.identity.username}</strong>{" "}
          <span className="muted">
            (roles: {me.roles.length > 0 ? me.roles.join(", ") : "none"})
          </span>
        </p>
      </header>
      {me.integrations.length === 0 ? (
        <p className="muted">
          No integrations authorized for your role yet. Ask your Lehen admin
          to map your role to one in the Hub admin UI.
        </p>
      ) : (
        <div className="connection-list">
          {me.integrations.map((integration) => (
            <ConnectionRow
              key={integration.instance_id}
              integration={integration}
              bearer={bearer}
              redirectUri={redirectUri}
              onConnectStarted={onConnectStarted}
              onError={onError}
            />
          ))}
        </div>
      )}
    </section>
  );
}

interface ConnectionRowProps {
  integration: MeIntegration;
  bearer: string;
  redirectUri: string;
  onConnectStarted: (instanceId: string) => void;
  onError: (message: string) => void;
}

function ConnectionRow({
  integration,
  bearer,
  redirectUri,
  onConnectStarted,
  onError,
}: ConnectionRowProps) {
  const [pending, setPending] = useState(false);

  const handleConnect = async () => {
    setPending(true);
    try {
      const { auth_url } = await initiateGrant(
        bearer,
        integration.instance_id,
        redirectUri,
      );
      // Tell App which instance the upcoming OAuth callback belongs to.
      onConnectStarted(integration.instance_id);
      await openExternal(auth_url);
      // Completion happens via deep-link → App routes back here for refresh.
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
      setPending(false);
    }
  };

  return (
    <div className="connection-row">
      <div>
        <div>
          <strong>{integration.display_name}</strong>{" "}
          <span className="muted">({integration.type})</span>
        </div>
        <div>
          <span className={`connection-status ${integration.status}`}>
            {integration.status.replace(/_/g, " ")}
          </span>
        </div>
      </div>
      {integration.status === "needs_connect" && (
        <button onClick={handleConnect} disabled={pending}>
          {pending ? "Opening browser…" : "Connect"}
        </button>
      )}
      {integration.status === "stale" && (
        <button onClick={handleConnect} disabled={pending}>
          Reconnect
        </button>
      )}
    </div>
  );
}
