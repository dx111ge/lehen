// Lehen user app. Vanilla JS, no build. Same PKCE plumbing as admin_ui;
// designed to be reusable by Tauri Edge later (D5).

const SPA_ROLE = "edge";
const REDIRECT_URI = window.location.origin + "/app/callback.html";

// ---------- shared utilities -------------------------------------------------

function setStatus(msg, isError) {
    const el = document.getElementById("status-bar");
    if (!el) return;
    el.textContent = msg || "";
    el.className = "status" + (isError ? " error" : "");
}

async function fetchJSON(url, opts = {}) {
    const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
    const tok = sessionStorage.getItem("lehen_access_token");
    if (tok) headers["Authorization"] = "Bearer " + tok;
    const r = await fetch(url, { ...opts, headers });
    if (r.status === 204) return null;
    const text = await r.text();
    let body;
    try { body = text ? JSON.parse(text) : null; } catch (e) { body = text; }
    if (!r.ok) {
        const detail = body && body.detail ? body.detail : (typeof body === "string" ? body : r.statusText);
        const err = new Error(`${r.status} ${detail}`);
        err.status = r.status;
        throw err;
    }
    return body;
}

function b64urlEncode(bytes) {
    return btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(text) {
    const data = new TextEncoder().encode(text);
    const buf = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(buf);
}

function randomVerifier() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return b64urlEncode(bytes);
}

// ---------- PKCE OIDC --------------------------------------------------------

async function loadAuthConfig() {
    const cached = sessionStorage.getItem("lehen_auth_config");
    if (cached) return JSON.parse(cached);
    const cfg = await (await fetch("/auth/public-config")).json();
    sessionStorage.setItem("lehen_auth_config", JSON.stringify(cfg));
    return cfg;
}

async function loadKeycloakWellKnown(authConfig) {
    const cacheKey = "lehen_kc_oidc";
    const cached = sessionStorage.getItem(cacheKey);
    if (cached) return JSON.parse(cached);
    const wk = await (await fetch(authConfig.well_known_url)).json();
    sessionStorage.setItem(cacheKey, JSON.stringify(wk));
    return wk;
}

async function startLogin() {
    const cfg = await loadAuthConfig();
    const wk = await loadKeycloakWellKnown(cfg);
    const verifier = randomVerifier();
    const challenge = b64urlEncode(await sha256(verifier));
    const state = randomVerifier();
    sessionStorage.setItem("lehen_pkce_verifier", verifier);
    sessionStorage.setItem("lehen_pkce_state", state);
    const params = new URLSearchParams({
        client_id: cfg.edge_client_id,
        response_type: "code",
        scope: "openid profile",
        redirect_uri: REDIRECT_URI,
        code_challenge: challenge,
        code_challenge_method: "S256",
        state: state,
    });
    window.location.href = wk.authorization_endpoint + "?" + params.toString();
}

async function handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    if (!code) return false;
    if (state !== sessionStorage.getItem("lehen_pkce_state")) {
        document.getElementById("callback-error").textContent = "CSRF state mismatch — refusing to continue.";
        return false;
    }
    const verifier = sessionStorage.getItem("lehen_pkce_verifier");
    const cfg = await loadAuthConfig();
    const wk = await loadKeycloakWellKnown(cfg);
    const body = new URLSearchParams({
        grant_type: "authorization_code",
        client_id: cfg.edge_client_id,
        code: code,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
    });
    const r = await fetch(wk.token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
    });
    if (!r.ok) {
        const t = await r.text();
        document.getElementById("callback-error").textContent = "Token exchange failed: " + t;
        return false;
    }
    const tokens = await r.json();
    sessionStorage.setItem("lehen_access_token", tokens.access_token);
    if (tokens.refresh_token) sessionStorage.setItem("lehen_refresh_token", tokens.refresh_token);
    sessionStorage.removeItem("lehen_pkce_verifier");
    sessionStorage.removeItem("lehen_pkce_state");
    window.location.replace("/app/");
    return true;
}

function signOut() {
    sessionStorage.clear();
    window.location.reload();
}

// ---------- /me + connection actions -----------------------------------------

async function renderMe() {
    const me = await fetchJSON("/me");
    document.getElementById("display-username").textContent = me.identity.username;
    document.getElementById("display-roles").textContent =
        me.roles.length ? me.roles.join(", ") : "(no roles match the SIAM mapping)";
    const list = document.getElementById("integration-list");
    list.innerHTML = "";
    if (me.integrations.length === 0) {
        const li = document.createElement("li");
        li.innerHTML = `<span class="meta">No integrations are allowed for your role(s) yet.
            Ask an admin to update the SIAM mapping.</span>`;
        list.appendChild(li);
        return;
    }
    for (const integ of me.integrations) {
        const li = document.createElement("li");
        const left = document.createElement("div");
        left.innerHTML = `<div class="name">${integ.display_name}</div>
            <div class="meta">${integ.type} &middot; ${integ.instance_id}</div>`;
        const right = document.createElement("div");
        const badge = document.createElement("span");
        badge.className = "status-badge " + integ.status;
        badge.textContent = integ.status.replace("_", " ");
        right.appendChild(badge);
        const btn = document.createElement("button");
        btn.style.marginLeft = "0.5rem";
        if (integ.status === "connected") {
            btn.textContent = "Disconnect";
            btn.addEventListener("click", () => doRevoke(integ.instance_id));
        } else {
            btn.className = "primary";
            btn.textContent = "Connect";
            btn.addEventListener("click", () => doGrant(integ.instance_id));
        }
        right.appendChild(btn);
        li.appendChild(left);
        li.appendChild(right);
        list.appendChild(li);
    }
}

async function doGrant(instanceId) {
    try {
        await fetchJSON("/me/connections/" + encodeURIComponent(instanceId), {
            method: "POST",
            body: JSON.stringify({ privacy_class: "company" }),
        });
        setStatus("Connected " + instanceId);
        await renderMe();
    } catch (e) {
        setStatus("Connect failed: " + e.message, true);
    }
}

async function doRevoke(instanceId) {
    if (!confirm("Disconnect " + instanceId + "?")) return;
    try {
        await fetchJSON("/me/connections/" + encodeURIComponent(instanceId), {
            method: "DELETE",
        });
        setStatus("Disconnected " + instanceId);
        await renderMe();
    } catch (e) {
        setStatus("Disconnect failed: " + e.message, true);
    }
}

// ---------- bootstrap --------------------------------------------------------

async function init() {
    if (window.location.pathname.endsWith("/callback.html")) {
        await handleCallback();
        return;
    }
    if (!sessionStorage.getItem("lehen_access_token")) {
        await startLogin();
        return;
    }
    try {
        document.getElementById("user-bar").classList.remove("hidden");
        document.getElementById("me-section").classList.remove("hidden");
        document.getElementById("signout-btn").addEventListener("click", signOut);
        await renderMe();
    } catch (e) {
        if (e.status === 401) {
            sessionStorage.removeItem("lehen_access_token");
            await startLogin();
            return;
        }
        setStatus(e.message, true);
    }
}

init();
