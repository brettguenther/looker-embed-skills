# Troubleshooting Looker CORS API, OAuth 2.0 PKCE, & Embedded OAuth Connections

---

## 1. Resolving `accounts.google.com` CSP `403` Errors on Embedded BigQuery OAuth Dashboards

### Symptom
A parent application authenticates the user via Google OAuth, completes the Looker OAuth 2.0 PKCE (`cors_api`) flow, and mounts an embedded Looker dashboard using `create_embed_url_as_me` (`POST /api/4.0/embed/token_url/me`). When the dashboard loads against a **BigQuery OAuth connection**, tiles fail with a "Log In" prompt; clicking it attempts to navigate the iframe to `https://accounts.google.com/o/oauth2/v2/auth`, which fails with an HTTP `403` / browser error (`Refused to frame 'https://accounts.google.com/' because an ancestor violates the following Content Security Policy directive: "frame-ancestors ..."`).

### Root Cause: Two Independent OAuth Layers in Looker
Looker separates application-level API/embed authentication from database connection OAuth authentication across two distinct credential layers:
1. **Looker Embed Application Session**: Populated by `cors_api` + `create_embed_url_as_me` (`POST /api/4.0/embed/token_url/me`). This endpoint generates a single-use embed URL with a 5-minute TTL redeemed via `GET /login/embed?t=<token>`.
2. **Database Connection OAuth Credentials**: Stores the per-user Google Cloud `access_token` and `refresh_token` required to run BigQuery jobs under the viewer's identity.

### Why In-Iframe BigQuery Login Fails
Authenticating via Looker OAuth PKCE only establishes Layer 1. When an embedded dashboard tile executes against a BigQuery OAuth connection without stored database credentials for that user:
1. The tile renders an in-tile "Log In" prompt.
2. Clicking the button attempts to navigate the iframe to `https://<looker_host>/external_oauth/authenticate/<app_id>...`.
3. Looker embed sessions restrict navigation to embed-allowed routes and block `/external_oauth/*` with **HTTP `403 Forbidden`**.
4. Even if navigated externally, `https://accounts.google.com/o/oauth2/v2/auth` cannot be framed inside an iframe because Google enforces `Content-Security-Policy: frame-ancestors` and `X-Frame-Options: DENY`.

---

### Architectural Resolutions

#### Option 1: Headless Token Seeding (`create_oauth_application_user_state`) — Recommended
Because the parent application already authenticates the user with Google OAuth before initiating Looker embedding:
1. **Share the Google OAuth 2.0 Client ID**: Configure the Looker BigQuery connection to use the **same custom Google Cloud OAuth 2.0 Client ID and Secret** as the parent web application.
2. **Request BigQuery Scopes at Parent Login**: Include `https://www.googleapis.com/auth/bigquery` (and `access_type=offline` if refresh tokens are needed) during the parent application's top-level Google login.
3. **Seed Database OAuth Tokens Before Mounting the Iframe**: From your backend (or via the Looker API), push the user's Google `access_token` and `refresh_token` directly into Looker using `create_oauth_application_user_state` (`POST /api/4.0/external_oauth_applications/user_state`) before loading the embedded dashboard:

```python
import datetime
import looker_sdk
from looker_sdk import models40 as models

sdk = looker_sdk.init40()

def seed_bigquery_oauth_tokens(
    looker_user_id: str,
    oauth_app_id: str,
    google_access_token: str,
    google_refresh_token: str,
    expires_in_seconds: int = 3500,
):
    expires_at = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(seconds=expires_in_seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    sdk.create_oauth_application_user_state(
        body=models.WriteOAuthUserStateRequest(
            user_id=looker_user_id,
            oauth_application_id=oauth_app_id,
            access_token=google_access_token,
            refresh_token=google_refresh_token,
            access_token_expires_at=expires_at,
        )
    )
```

#### Option 2: Top-Level Popup Pre-Authentication (Before Embedding)
If backend token seeding is not viable, the browser must complete BigQuery OAuth in a top-level popup window (`window.open`) **prior** to redeeming `GET /login/embed?t=<token>`:
1. For a custom OAuth application, open a popup to `https://<looker_host>/external_oauth/authenticate/<oauth_app_id>?redirect_url=https://<looker_host>/external_oauth/success`.
2. For Looker (Google Cloud core) Google OAuth (`system_google`), open a popup to `https://<looker_host>/external_oauth/authorize_system_application/system_google?redirect_url=https://<looker_host>/external_oauth/success`.
3. Only after the popup finishes and saves the user's BigQuery OAuth credentials should the parent application call `create_embed_url_as_me` and mount the embed iframe. Once `/login/embed?t=<token>` starts the embed session, `/external_oauth/*` is blocked with HTTP `403`.

#### Option 3: Parameterized Service Account Impersonation (`impersonated_service_account`)
If per-user OAuth was chosen only for dataset isolation or cost auditing rather than end-user Google Drive permissions, switch the BigQuery connection to GCP Service Account / ADC authentication:
1. On Looker (Google Cloud core), bind the BigQuery connection's `impersonated_service_account` attribute to a Looker User Attribute via `PATCH /api/4.0/connections/{name}` with `{"user_attribute_fields": ["impersonated_service_account"], "impersonated_service_account": "<user_attr_name>"}`.
2. Queries execute under per-tenant or per-role GCP IAM service accounts without requiring any per-user Google OAuth browser flow.

---

## 2. Common OAuth 2.0 PKCE & CORS Errors

| Error / Symptom | Root Cause | Resolution |
| :--- | :--- | :--- |
| **`400 Bad Request` on `/auth` or `/api/token` (`Invalid redirect_uri`)** | `redirect_uri` contains a wildcard (`*`), trailing slash mismatch, dynamic subpath, or query string. | Register exact callback URLs in `redirect_uris: string[]` and pass dynamic return routes via the OAuth `state` parameter or `sessionStorage`. |
| **CORS Preflight (`OPTIONS`) Fails with `403 Forbidden`** | Frontend origin (`https://host:port`) is missing from Looker's Embedded Domain Allowlist. | Add the exact protocol, hostname, and port (no trailing slash) to **Admin > Embed > Embedded Domain Allowlist**. |
| **`403 Forbidden` on `/external_oauth/*` inside iframe** | Embed sessions initiated via `/login/embed` restrict navigation to embed-allowed routes and disallow `/external_oauth/*`. | Complete database OAuth in a top-level popup *prior* to iframe mounting, or seed database OAuth tokens headlessly via backend API. |
| **`window.crypto.subtle is undefined` during PKCE challenge generation** | Browser disables Web Crypto API on non-secure (`http://`) origins other than `localhost`/`127.0.0.1`. | Serve local and staging environments over `https://` (`HTTPS=true` or Vite `@vitejs/plugin-basic-ssl`). |
| **`401 Unauthorized` after page reload** | Default `OAuthSession` stores tokens in volatile JS memory only. | Use `PersistentOAuthSession` backed by `sessionStorage` (see `sdk_code_patterns.md`). |
| **Token has already been used on `create_embed_url_as_me` reload** | Embed URL token is single-consumption with a 5-minute TTL; a second load triggers a redirect to `/login`. | Do not reuse the signed embed URL; generate a fresh embed URL on each mount, and set `"force_logout_login": false` in `POST /api/4.0/embed/token_url/me` if preserving existing session state. |
