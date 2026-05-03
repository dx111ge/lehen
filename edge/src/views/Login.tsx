import { useState } from "react";

import { beginHubLogin } from "../auth/pkce";

interface LoginProps {
  hubUrl: string;
  providerLabel: string;
  onError: (message: string) => void;
}

/**
 * Kicks off the Hub-login OIDC PKCE flow. Shows a single button — the
 * actual UI state machine (browser opens, user consents, deep-link comes
 * back) is driven by the App component's deep-link subscription.
 */
export function Login({ hubUrl, providerLabel, onError }: LoginProps) {
  const [pending, setPending] = useState(false);

  const handleClick = async () => {
    setPending(true);
    try {
      await beginHubLogin();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setPending(false);
    }
  };

  return (
    <div>
      <p>
        This Edge is configured to talk to{" "}
        <strong>{hubUrl}</strong>, which uses{" "}
        <strong>{providerLabel}</strong> for sign-in.
      </p>
      <p className="muted">
        Clicking sign-in opens your default browser. After you authenticate,
        the browser hands control back to Lehen Edge automatically.
      </p>
      <button onClick={handleClick} disabled={pending}>
        {pending ? "Opening browser…" : `Sign in with ${providerLabel}`}
      </button>
    </div>
  );
}
