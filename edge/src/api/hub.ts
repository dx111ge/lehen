// Thin Hub HTTP client. Uses Tauri's HTTP plugin (`@tauri-apps/plugin-http`)
// rather than the webview's native fetch — the webview lives at a separate
// origin (``tauri://localhost``) from the Hub, so native fetch hits CORS.
// The plugin routes requests through the Rust side; no CORS preflight,
// and it gives us a proper desktop HTTP client (timeouts, redirects).
//
// The Hub URL is read once from the Tauri side at startup; it does not
// change at runtime.

import { invoke } from "@tauri-apps/api/core";
import { fetch } from "@tauri-apps/plugin-http";

import type {
  AuthPublicConfig,
  ConnectionRecord,
  InitiateGrantResponse,
  MeResponse,
} from "./types";

interface EdgeConfig {
  hub_url: string;
  auth_callback_path: string;
  oauth_callback_path: string;
}

let cachedConfig: EdgeConfig | null = null;

export async function getEdgeConfig(): Promise<EdgeConfig> {
  if (cachedConfig === null) {
    cachedConfig = await invoke<EdgeConfig>("get_edge_config");
  }
  return cachedConfig;
}

export async function fetchAuthPublicConfig(): Promise<AuthPublicConfig> {
  const { hub_url } = await getEdgeConfig();
  const response = await fetch(`${hub_url}/auth/public-config`, {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new HubError(
      `auth public-config failed: ${response.status} ${response.statusText}`,
      response.status,
    );
  }
  return (await response.json()) as AuthPublicConfig;
}

export async function fetchMe(bearer: string): Promise<MeResponse> {
  const { hub_url } = await getEdgeConfig();
  const response = await fetch(`${hub_url}/me`, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${bearer}`,
    },
  });
  if (!response.ok) {
    throw new HubError(
      `/me failed: ${response.status} ${response.statusText}`,
      response.status,
    );
  }
  return (await response.json()) as MeResponse;
}

export async function initiateGrant(
  bearer: string,
  instanceId: string,
  redirectUri: string,
): Promise<InitiateGrantResponse> {
  const { hub_url } = await getEdgeConfig();
  const response = await fetch(
    `${hub_url}/me/connections/${encodeURIComponent(instanceId)}/initiate`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${bearer}`,
      },
      body: JSON.stringify({ redirect_uri: redirectUri }),
    },
  );
  if (!response.ok) {
    throw new HubError(
      await formatHubError("initiate", response),
      response.status,
    );
  }
  return (await response.json()) as InitiateGrantResponse;
}

export async function completeGrant(
  bearer: string,
  instanceId: string,
  code: string,
  state: string,
): Promise<ConnectionRecord> {
  const { hub_url } = await getEdgeConfig();
  const response = await fetch(
    `${hub_url}/me/connections/${encodeURIComponent(instanceId)}/complete`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${bearer}`,
      },
      body: JSON.stringify({ code, state }),
    },
  );
  if (!response.ok) {
    throw new HubError(
      await formatHubError("complete", response),
      response.status,
    );
  }
  return (await response.json()) as ConnectionRecord;
}

export class HubError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "HubError";
  }
}

async function formatHubError(
  step: string,
  response: Response,
): Promise<string> {
  // Include the body's ``detail`` field if FastAPI sent one — that's where
  // the actual reason lives (token-endpoint upstream error, OAuth state
  // mismatch, etc.). Without this the user sees only the HTTP status.
  let detail = "";
  try {
    const text = await response.text();
    if (text) {
      try {
        const body = JSON.parse(text) as { detail?: string };
        detail = body?.detail ?? text;
      } catch {
        detail = text;
      }
    }
  } catch {
    // body read failed — fall through with empty detail
  }
  const suffix = detail ? `: ${detail}` : "";
  return `${step} failed: ${response.status} ${response.statusText}${suffix}`;
}
