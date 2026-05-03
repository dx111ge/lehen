# How to Set Up Microsoft Entra for Lehen

This guide walks through configuring a Microsoft Entra (Azure AD) application registration for a new Lehen deployment. Follow these steps for any new environment (dev, staging, prod).

---

## Prerequisites

- A Microsoft Entra tenant (Azure subscription with Entra ID, or M365 tenant)
- Global Administrator or Application Administrator role in the tenant
- Access to [https://entra.microsoft.com](https://entra.microsoft.com) or [https://portal.azure.com](https://portal.azure.com)

---

## Step 1 — Create the App Registration

1. Go to **Microsoft Entra Admin Center** → **App registrations** → **New registration**
2. Fill in:
   - **Name**: `lehen-hub-<env>` (e.g. `lehen-hub-dev`, `lehen-hub-prod`)
   - **Supported account types**: *Accounts in this organizational directory only (Single tenant)*
   - **Redirect URI**: leave blank for now
3. Click **Register**
4. Note down the **Application (client) ID** and **Directory (tenant) ID** from the Overview page

---

## Step 2 — Configure Redirect URIs

1. Go to **Authentication** (or *Authentication (Preview)*)
2. Click **Add a platform** → **Mobile and desktop applications**
3. Add the following custom URIs:
   - `lehen://oauth/callback`
   - `lehen://auth/callback`
4. Ensure the platform type is **Public client / native** (not Web, not SPA)
5. Click **Save** / **Configure**

---

## Step 3 — Create a Client Secret

1. Go to **Certificates & secrets** → **Client secrets** → **New client secret**
2. Description: `lehen-<env>-secret`
3. Expiry: choose appropriate duration (e.g. 24 months)
4. Click **Add**
5. **Copy the secret Value immediately** — it cannot be retrieved after leaving this page
6. Store it securely (e.g. in your secrets manager / .env file)

---

## Step 4 — Expose an API

1. Go to **Expose an API**
2. Click **Set** next to *Application ID URI*
3. Accept the default: `api://<client-id>` and click **Save**
4. Click **Add a scope**:
   - **Scope name**: `access_as_user`
   - **Who can consent**: *Admins and users*
   - **Admin consent display name**: `Access Lehen as user`
   - **Admin consent description**: `Allows the application to access Lehen on behalf of the signed-in user`
   - **State**: *Enabled*
5. Click **Add scope**

---

## Step 5 — Create the App Role

1. Go to **App roles** → **Create app role**
2. Fill in:
   - **Display name**: `Lehen Admin`
   - **Allowed member types**: *Users/Groups*
   - **Value**: `lehen-admin`
   - **Description**: `Full administrative access to Lehen`
   - **Enable this app role**: ✅ checked
3. Click **Apply**

---

## Step 6 — Configure API Permissions

1. Go to **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions**
2. Search and select the following scopes:
   - `openid`
   - `profile`
   - `email`
   - `offline_access`
   - `User.Read`
   - `Mail.Read`
3. Click **Add permissions**
4. Click **Grant admin consent for <tenant>** and confirm
5. Verify all permissions show a green ✅ *Granted* status

---

## Step 7 — Assign Users to the Lehen Admin Role

1. Go to **Microsoft Entra Admin Center** → **Enterprise applications**
2. Search for and open your `lehen-hub-<env>` app
3. Go to **Users and groups** → **Add user/group**
4. Select the user(s) who should have admin access
5. Under **Select a role**, choose **Lehen Admin**
6. Click **Assign**

> **Alternative (CLI):** Use Azure Cloud Shell with:
> ```bash
> # Get user object ID
> USER_ID=$(az ad user show --id <upn> --query id -o tsv)
>
> # Get app role ID
> ROLE_ID=$(az ad app show --id <client-id> --query "appRoles[?value=='lehen-admin'].id" -o tsv)
>
> # Get service principal object ID
> SP_ID=$(az ad sp show --id <client-id> --query id -o tsv)
>
> # Assign role via Graph API
> az rest --method POST \
>   --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignedTo" \
>   --body "{\"principalId\":\"${USER_ID}\",\"resourceId\":\"${SP_ID}\",\"appRoleId\":\"${ROLE_ID}\"}"
> ```

---

## Step 8 — Configure hub/.env

Add the following variables to your Hub's `.env` file:

```env
LEHEN_IDENTITY_PROVIDER=entra

LEHEN_ENTRA__TENANT_ID=<directory-tenant-id>
LEHEN_ENTRA__AUDIENCE=api://<client-id>
LEHEN_ENTRA__ADMIN_ROLE=lehen-admin
LEHEN_ENTRA__EDGE_CLIENT_ID=<client-id>
LEHEN_ENTRA__ADMIN_UI_CLIENT_ID=<client-id>
LEHEN_ENTRA__CLIENT_SECRET=<client-secret-value>
```

---

## Step 9 — Verify the Setup

1. Boot ArcadeDB and the Hub service
2. Check `GET /health/ready` returns HTTP 200
3. Attempt an OIDC sign-in flow from the Edge client using the tenant credentials
4. Verify the access token contains the `roles` claim with value `lehen-admin`

---

## Notes

- The same `client_id` is used for: SIAM sign-in (Edge), the Admin UI, and the outlook-graph source adapter
- `Mail.Read` is required for the outlook-graph data source adapter
- `offline_access` is required for refresh token support
- App roles only appear in tokens when the user has an explicit assignment in Enterprise Applications → Users and groups
