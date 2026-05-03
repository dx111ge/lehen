// Lehen Admin SPA. Vanilla JS, no build step.
//
// Two sign-in paths:
//   1. SSO via the active SIAM IdP (Keycloak or Entra; the SPA picks the right
//      client_id from /auth/public-config). Standard OIDC PKCE flow.
//   2. Local admin bootstrap/break-glass (POST /admin/local-login). Surfaced
//      so a fresh deployment can be configured before SSO works, and so an
//      operator can recover after an SSO outage.
//
// Tokens land in sessionStorage either way; the rest of the SPA does not
// know or care which path produced them.

const SPA_ROLE = "admin";
const REDIRECT_URI = window.location.origin + "/admin/callback.html";

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
    try {
        body = text ? JSON.parse(text) : null;
    } catch (e) {
        body = text;
    }
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

async function loadIdpWellKnown(authConfig) {
    // OIDC discovery is identical across Keycloak and Entra at the protocol
    // level; this cache is per-page-load and is provider-agnostic.
    const cacheKey = "lehen_idp_oidc";
    const cached = sessionStorage.getItem(cacheKey);
    if (cached) return JSON.parse(cached);
    const wk = await (await fetch(authConfig.well_known_url)).json();
    sessionStorage.setItem(cacheKey, JSON.stringify(wk));
    return wk;
}

async function startLogin() {
    const cfg = await loadAuthConfig();
    const wk = await loadIdpWellKnown(cfg);
    const verifier = randomVerifier();
    const challenge = b64urlEncode(await sha256(verifier));
    const state = randomVerifier();
    sessionStorage.setItem("lehen_pkce_verifier", verifier);
    sessionStorage.setItem("lehen_pkce_state", state);
    const params = new URLSearchParams({
        client_id: SPA_ROLE === "admin" ? cfg.admin_ui_client_id : cfg.edge_client_id,
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
    const expectedState = sessionStorage.getItem("lehen_pkce_state");
    if (state !== expectedState) {
        document.getElementById("callback-error").textContent = "CSRF state mismatch — refusing to continue.";
        return false;
    }
    const verifier = sessionStorage.getItem("lehen_pkce_verifier");
    const cfg = await loadAuthConfig();
    const wk = await loadIdpWellKnown(cfg);
    const body = new URLSearchParams({
        grant_type: "authorization_code",
        client_id: SPA_ROLE === "admin" ? cfg.admin_ui_client_id : cfg.edge_client_id,
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
    window.location.replace("/admin/");
    return true;
}

function signOut() {
    sessionStorage.clear();
    window.location.reload();
}

// ---------- local-admin login ------------------------------------------------

async function localAdminLogin(username, password) {
    // POST /admin/local-login is the one path on the admin surface that
    // accepts unauthenticated POST. Vague 401 on every failure regardless of
    // the actual reason — match the contract by displaying the server's
    // detail verbatim and not trying to interpret it.
    const r = await fetch("/admin/local-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
    });
    const text = await r.text();
    let body;
    try {
        body = text ? JSON.parse(text) : null;
    } catch (e) {
        body = text;
    }
    if (!r.ok) {
        const detail = body && body.detail ? body.detail : (typeof body === "string" ? body : r.statusText);
        const err = new Error(detail);
        err.status = r.status;
        throw err;
    }
    sessionStorage.setItem("lehen_access_token", body.access_token);
    return body;
}

// ---------- admin panes ------------------------------------------------------

let _types = [];
let _llmProviders = [];
let _llmCurrent = null;

function _providerById(id) {
    return _llmProviders.find(p => p.id === id);
}

function renderProviderFields(side) {
    const select = document.querySelector(`select[data-side="${side}"]`);
    const targetWrap = document.querySelector(`.provider-fields[data-side="${side}"]`);
    const descEl = document.querySelector(`.provider-description[data-side="${side}"]`);
    const provider = _providerById(select.value);
    targetWrap.innerHTML = "";
    if (!provider) {
        descEl.textContent = "";
        return;
    }
    descEl.textContent = provider.description || "";
    descEl.classList.toggle("warn", provider.id === "openai");
    const sideState = (_llmCurrent && _llmCurrent[side]) || {};
    for (const f of provider.fields) {
        const wrap = document.createElement("label");
        wrap.style.display = "block";
        wrap.style.marginTop = "0.6rem";

        const labelText = document.createElement("span");
        labelText.textContent = f.label + (f.required ? " *" : "");
        wrap.appendChild(labelText);

        if (f.secret) {
            const isSet = !!sideState[`${f.name}_set`];
            const badge = document.createElement("span");
            badge.className = "secret-status" + (isSet ? "" : " empty");
            badge.textContent = isSet ? "value stored" : "not set";
            wrap.appendChild(badge);
        }

        const input = document.createElement("input");
        input.name = `${side}.${f.name}`;
        input.dataset.side = side;
        input.dataset.field = f.name;
        input.dataset.secret = f.secret ? "1" : "0";
        if (f.secret) {
            input.type = "password";
            input.placeholder = sideState[`${f.name}_set`]
                ? "(leave empty to keep current; type a new value to replace; type only spaces to clear)"
                : f.placeholder || "";
        } else {
            input.type = f.field_type === "url" ? "url" : "text";
            if (f.placeholder) input.placeholder = f.placeholder;
            if (sideState[f.name] !== undefined) input.value = sideState[f.name];
        }
        wrap.appendChild(input);

        if (f.description) {
            const help = document.createElement("p");
            help.className = "field-help";
            help.textContent = f.description;
            wrap.appendChild(help);
        }
        targetWrap.appendChild(wrap);
    }
}

async function loadLLMPane() {
    if (!_llmProviders.length) {
        _llmProviders = await fetchJSON("/admin/llm/providers");
    }
    _llmCurrent = await fetchJSON("/admin/llm");

    for (const side of ["inference", "embedding"]) {
        const select = document.querySelector(`select[data-side="${side}"]`);
        select.innerHTML = "";
        for (const p of _llmProviders) {
            const opt = document.createElement("option");
            opt.value = p.id;
            opt.textContent = p.display_name;
            select.appendChild(opt);
        }
        const current = (_llmCurrent[side] && _llmCurrent[side].provider) || _llmProviders[0].id;
        select.value = current;
        select.onchange = () => renderProviderFields(side);
        renderProviderFields(side);
    }

    document.getElementById("llm-meta").textContent =
        `Last updated by ${_llmCurrent.updated_by || "?"} at ${_llmCurrent.updated_at || "?"}`;
}

function _collectSidePayload(form, side) {
    const provider = form.elements[`${side}.provider`].value;
    const payload = { provider };
    const sideState = (_llmCurrent && _llmCurrent[side]) || {};
    const providerSpec = _providerById(provider);
    if (!providerSpec) return payload;
    for (const f of providerSpec.fields) {
        const input = form.querySelector(`input[name="${side}.${f.name}"]`);
        if (!input) continue;
        const raw = input.value;
        if (f.secret) {
            // Only send if user actually typed something. If the field is left
            // empty and the user already had a stored value, we keep it (omit
            // from payload). To explicitly clear, the user types whitespace
            // (we send empty string).
            if (raw === "" && sideState[`${f.name}_set`]) {
                continue;
            }
            if (raw.trim() === "" && raw !== "") {
                payload[f.name] = "";  // explicit clear
            } else if (raw !== "") {
                payload[f.name] = raw;
            }
        } else if (raw !== "" || f.required) {
            payload[f.name] = raw;
        }
    }
    return payload;
}

async function saveLLM(ev) {
    ev.preventDefault();
    const form = ev.target;
    const body = {
        inference: _collectSidePayload(form, "inference"),
        embedding: _collectSidePayload(form, "embedding"),
    };
    try {
        await fetchJSON("/admin/llm", { method: "PUT", body: JSON.stringify(body) });
        setStatus("LLM config saved");
        await loadLLMPane();
    } catch (e) {
        setStatus("Save failed: " + e.message, true);
    }
}

async function loadIntegrationsPane() {
    _types = await fetchJSON("/admin/integrations/types");
    const tlist = document.getElementById("integration-types");
    tlist.innerHTML = "";
    for (const t of _types) {
        const li = document.createElement("li");
        li.innerHTML = `<strong>${t.id}</strong> &mdash; ${t.display_name}`;
        tlist.appendChild(li);
    }
    const select = document.getElementById("integration-type-select");
    select.innerHTML = "";
    for (const t of _types) {
        const o = document.createElement("option");
        o.value = t.id;
        o.textContent = `${t.display_name} (${t.id})`;
        select.appendChild(o);
    }
    select.addEventListener("change", renderConfigFields);
    renderConfigFields();

    const ilist = document.getElementById("integration-instances");
    const instances = await fetchJSON("/admin/integrations");
    ilist.innerHTML = "";
    for (const inst of instances) {
        const li = document.createElement("li");
        const secrets = (inst.secret_fields_set || []).join(", ") || "—";
        li.innerHTML = `<strong>${inst.id}</strong> (${inst.type}) — ${inst.display_name}
            <button data-id="${inst.id}" class="del-btn">Delete</button><br>
            <code>config_public: ${JSON.stringify(inst.config_public || {})}</code><br>
            <code>secrets set: ${secrets}</code>`;
        ilist.appendChild(li);
    }
    for (const btn of ilist.querySelectorAll(".del-btn")) {
        btn.addEventListener("click", async () => {
            const id = btn.dataset.id;
            if (!confirm("Delete " + id + "?")) return;
            try {
                await fetchJSON("/admin/integrations/" + encodeURIComponent(id), { method: "DELETE" });
                await loadIntegrationsPane();
            } catch (e) {
                setStatus("Delete failed: " + e.message, true);
            }
        });
    }
}

function renderConfigFields() {
    const select = document.getElementById("integration-type-select");
    const t = _types.find(x => x.id === select.value);
    const target = document.getElementById("integration-config-fields");
    target.innerHTML = "";
    if (!t) return;
    for (const f of t.fields) {
        const label = document.createElement("label");
        label.textContent = f.label + (f.required ? " *" : "");
        const input = document.createElement("input");
        input.name = "config." + f.name;
        if (f.secret) input.type = "password";
        if (f.placeholder) input.placeholder = f.placeholder;
        if (f.required) input.required = true;
        label.appendChild(input);
        if (f.description) {
            const small = document.createElement("small");
            small.textContent = f.description;
            label.appendChild(document.createElement("br"));
            label.appendChild(small);
        }
        target.appendChild(label);
    }
}

async function createIntegration(ev) {
    ev.preventDefault();
    const form = ev.target;
    const config = {};
    let body = { config };
    for (const el of form.elements) {
        if (!el.name) continue;
        if (el.name.startsWith("config.")) {
            if (el.value !== "") config[el.name.slice("config.".length)] = el.value;
        } else if (el.type === "checkbox") {
            body[el.name] = el.checked;
        } else if (el.value !== "") {
            body[el.name] = el.value;
        }
    }
    try {
        await fetchJSON("/admin/integrations", { method: "POST", body: JSON.stringify(body) });
        setStatus("Instance created");
        form.reset();
        await loadIntegrationsPane();
    } catch (e) {
        setStatus("Create failed: " + e.message, true);
    }
}

async function loadSiamPane() {
    const r = await fetchJSON("/admin/siam");
    document.getElementById("siam-textarea").value = JSON.stringify(r.mapping, null, 2);
}

async function saveSiam() {
    const text = document.getElementById("siam-textarea").value;
    let mapping;
    try {
        mapping = JSON.parse(text);
    } catch (e) {
        setStatus("Invalid JSON: " + e.message, true);
        return;
    }
    try {
        await fetchJSON("/admin/siam", { method: "PUT", body: JSON.stringify({ mapping }) });
        setStatus("SIAM mapping saved");
        await loadSiamPane();
    } catch (e) {
        setStatus("Save failed: " + e.message, true);
    }
}

async function loadAuditPane() {
    const r = await fetchJSON("/admin/audit?limit=50");
    const list = document.getElementById("audit-list");
    list.innerHTML = "";
    for (const item of (r.items || [])) {
        const li = document.createElement("li");
        li.innerHTML = `<strong>${item.ts}</strong> &mdash; ${item.actor_username}
            <em>${item.action}</em> on <code>${item.target_id || "—"}</code>
            <code>before=${JSON.stringify(item.before)}\nafter=${JSON.stringify(item.after)}</code>`;
        list.appendChild(li);
    }
}

// ---------- bootstrap --------------------------------------------------------

function showApp() {
    document.getElementById("user-bar").classList.remove("hidden");
    document.getElementById("tabs").classList.remove("hidden");
    const loginPane = document.getElementById("pane-login");
    if (loginPane) loginPane.classList.add("hidden");
    document.getElementById("pane-llm").classList.remove("hidden");
}

const PROVIDER_LABEL = { keycloak: "Keycloak", entra: "Microsoft Entra" };

async function showLoginPane() {
    const loginPane = document.getElementById("pane-login");
    loginPane.classList.remove("hidden");
    // Populate the SSO label from the active provider.
    try {
        const cfg = await loadAuthConfig();
        const label = PROVIDER_LABEL[cfg.provider] || cfg.provider;
        document.getElementById("sso-provider-label").textContent =
            "Active provider: " + label;
    } catch (e) {
        document.getElementById("sso-provider-label").textContent =
            "(could not reach Hub for provider config)";
    }
    document.getElementById("sso-login-btn").addEventListener("click", () => {
        startLogin().catch((e) => setStatus(e.message, true));
    });
    document.getElementById("local-login-form").addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const errEl = document.getElementById("local-login-error");
        errEl.textContent = "";
        const form = ev.target;
        const username = form.elements.username.value;
        const password = form.elements.password.value;
        try {
            await localAdminLogin(username, password);
            // Reload from /admin/ so init() runs the authenticated path.
            window.location.replace("/admin/");
        } catch (e) {
            errEl.textContent = e.message || "authentication failed";
        }
    });
}

async function showAuthenticatedApp() {
    const who = await fetchJSON("/admin/whoami");
    const sourceLabel = who.identity_source === "lehen-hub-local"
        ? " (local admin)"
        : " (admin)";
    document.getElementById("user-name").textContent = who.username + sourceLabel;
    showApp();
    await loadLLMPane();
    document.getElementById("llm-form").addEventListener("submit", saveLLM);
    document.getElementById("integration-create-form").addEventListener("submit", createIntegration);
    document.getElementById("siam-save-btn").addEventListener("click", saveSiam);
    document.getElementById("audit-refresh-btn").addEventListener("click", loadAuditPane);
    document.getElementById("signout-btn").addEventListener("click", signOut);
    for (const tab of document.querySelectorAll(".tab")) {
        tab.addEventListener("click", () => {
            for (const t of document.querySelectorAll(".tab")) t.classList.remove("active");
            tab.classList.add("active");
            for (const p of document.querySelectorAll(".pane")) p.classList.add("hidden");
            const target = document.getElementById("pane-" + tab.dataset.pane);
            target.classList.remove("hidden");
            if (tab.dataset.pane === "integrations") loadIntegrationsPane();
            if (tab.dataset.pane === "siam") loadSiamPane();
            if (tab.dataset.pane === "audit") loadAuditPane();
        });
    }
}

async function init() {
    if (window.location.pathname.endsWith("/callback.html")) {
        await handleCallback();
        return;
    }
    if (!sessionStorage.getItem("lehen_access_token")) {
        await showLoginPane();
        return;
    }
    try {
        await showAuthenticatedApp();
    } catch (e) {
        if (e.status === 401) {
            sessionStorage.removeItem("lehen_access_token");
            await showLoginPane();
            return;
        }
        setStatus(e.message, true);
    }
}

init();
