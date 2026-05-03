// Shapes mirroring the Hub API responses. Keep this file authoritative —
// when the Hub adds fields, surface them here too. The Hub's response
// schemas live under hub/src/lehen_hub/api/.

export interface AuthPublicConfig {
  provider: "keycloak" | "entra";
  issuer: string;
  well_known_url: string;
  realm: string; // Keycloak realm name OR Entra tenant id; provider disambiguates
  edge_client_id: string;
  admin_ui_client_id: string;
  audience: string;
}

export interface MeIntegration {
  instance_id: string;
  type: string;
  display_name: string;
  status: "needs_connect" | "connected" | "stale";
  connection_id: string | null;
}

export interface MeResponse {
  identity: { sub: string; username: string };
  roles: string[];
  integrations: MeIntegration[];
}

export interface InitiateGrantResponse {
  auth_url: string;
  state: string;
}

export interface ConnectionRecord {
  id: string;
  user_sub: string;
  username: string;
  integration_instance_id: string;
  connection_seq: number;
  external_subject: string;
  display_label: string;
  privacy_class: string;
  status: string;
  connected_at: string;
  disconnected_at: string | null;
  last_health_status: string | null;
}

// OIDC discovery — what the Edge fetches from the IdP's well-known URL.
export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
}
