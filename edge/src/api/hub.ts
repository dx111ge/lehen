// Thin Hub HTTP client. Uses the system fetch (Tauri's webview is
// Chromium-based, so standard fetch + CORS works). The Hub URL is read
// once from the Tauri side at startup; it does not change at runtime.

import { invoke } from "@tauri-apps/api/core";

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
      `initiate failed: ${response.status} ${response.statusText}`,
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
      `complete failed: ${response.status} ${response.statusText}`,
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
