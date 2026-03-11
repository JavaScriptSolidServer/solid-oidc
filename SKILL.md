# Solid-OIDC — Authentication for Solid Apps

Authenticate users with Solid pods using Solid-OIDC. Zero dependencies, zero build step, single file.

## What This Skill Does

Implements the complete Solid-OIDC authentication flow in the browser: login, token refresh, logout, and authenticated fetch with DPoP proof-of-possession tokens.

## Quick Start

```html
<script type="module">
  import { Session } from 'https://esm.sh/gh/JavaScriptSolidServer/solid-oidc/solid-oidc.js'

  const session = new Session({
    onStateChange: (e) => {
      console.log(e.detail.isActive ? `Logged in as ${e.detail.webId}` : 'Not logged in')
    }
  })

  // Restore previous session
  session.restore().catch(() => {})

  // Handle redirect from identity provider
  session.handleRedirectFromLogin()
</script>
```

## Authentication Flow

```
1. session.login(idp, redirectUri)
   ├── Discover OIDC config:  GET {idp}/.well-known/openid-configuration
   ├── Register client:       POST registration_endpoint
   ├── Generate PKCE:         code_verifier + code_challenge (S256)
   └── Redirect to:           authorization_endpoint?response_type=code&...

2. User authenticates at identity provider

3. Redirect back with ?code=...&iss=...&state=...

4. session.handleRedirectFromLogin()
   ├── Verify issuer (RFC 9207)
   ├── Verify CSRF state
   ├── Generate DPoP key pair (ES256 / P-256)
   ├── Exchange code for tokens: POST token_endpoint
   ├── Validate access token (signature, issuer, audience, DPoP binding)
   ├── Store refresh token in IndexedDB
   └── Emit sessionStateChange event

5. session.authFetch(url)
   ├── Create DPoP proof (RFC 9449)
   ├── Set Authorization: DPoP {access_token}
   ├── Set DPoP: {proof_jwt}
   └── fetch(url, { headers })
```

## Session API

### Constructor

```js
const session = new Session({
  clientId: null,              // Pre-registered client ID (skips dynamic registration)
  database: new SessionDatabase(), // IndexedDB store for session persistence
  onStateChange: (e) => {},    // { isActive, webId }
  onExpirationWarning: (e) => {}, // { expires_in }
  onExpiration: () => {}       // Token expired, refresh failed
})
```

### Methods

| Method | Description |
|--------|-------------|
| `session.login(idp, redirectUri)` | Redirect to identity provider |
| `session.handleRedirectFromLogin()` | Handle redirect, exchange code for tokens |
| `session.restore()` | Restore session from stored refresh token |
| `session.logout()` | Clear session and stored data |
| `session.authFetch(url, options)` | Authenticated fetch with DPoP |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `session.isActive` | `boolean` | User is logged in |
| `session.webId` | `string` | User's WebID URI |
| `session.isExpired()` | `boolean` | Access token expired |
| `session.getExpiresIn()` | `number` | Seconds until expiry |

### Events

| Event | Detail | When |
|-------|--------|------|
| `sessionStateChange` | `{ isActive, webId }` | Login or logout |
| `sessionExpirationWarning` | `{ expires_in }` | Refresh failed, not yet expired |
| `sessionExpiration` | — | Expired and refresh failed |

## OIDC Discovery

Every Solid identity provider exposes:

```
GET {idp}/.well-known/openid-configuration
```

Key fields:

| Field | Purpose |
|-------|---------|
| `issuer` | Canonical issuer URI |
| `authorization_endpoint` | Where to send user for login |
| `token_endpoint` | Where to exchange code for tokens |
| `registration_endpoint` | Dynamic client registration |
| `jwks_uri` | Public keys for token verification |

## Dynamic Client Registration

If no `clientId` is provided, the library registers automatically:

```json
{
  "application_type": "web",
  "redirect_uris": ["https://myapp.example/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid offline_access webid"
}
```

## DPoP (Demonstration of Proof-of-Possession)

Every authenticated request includes a DPoP proof JWT:

```
Authorization: DPoP {access_token}
DPoP: {proof_jwt}
```

The DPoP proof contains:

| Claim | Value |
|-------|-------|
| `htu` | Target URL (origin + path) |
| `htm` | HTTP method (GET, PUT, etc.) |
| `iat` | Current timestamp |
| `jti` | Unique identifier |
| `ath` | Access token hash (when bound) |

The access token's `cnf.jkt` claim must match the DPoP key's thumbprint (RFC 7638).

## PKCE (Proof Key for Code Exchange)

Prevents authorization code interception:

| Parameter | Value |
|-----------|-------|
| `code_challenge_method` | `S256` |
| `code_challenge` | `BASE64URL(SHA256(code_verifier))` |
| `code_verifier` | Random string sent at token exchange |

## Access Token Claims

The Solid-OIDC access token contains:

| Claim | Purpose |
|-------|---------|
| `webid` | User's WebID URI |
| `iss` | Issuer (identity provider) |
| `aud` | Audience (`solid`) |
| `exp` | Expiration timestamp |
| `iat` | Issued at timestamp |
| `client_id` | Registered client identifier |
| `cnf.jkt` | DPoP key thumbprint (proof-of-possession binding) |

## Token Refresh

Sessions persist across page reloads via IndexedDB:

```js
// On page load, try to restore
try {
  await session.restore()  // Uses stored refresh_token
} catch {
  // No session to restore
}
```

The refresh flow:
1. Read `refresh_token`, `token_endpoint`, `client_id`, `dpop_keypair` from IndexedDB
2. `POST token_endpoint` with `grant_type=refresh_token`
3. Store new refresh token
4. Update session state

## Common Patterns

### Login / Logout Buttons

```js
document.getElementById('login').onclick = () =>
  session.login('https://solidcommunity.net', window.location.href)

document.getElementById('logout').onclick = () =>
  session.logout()
```

### Read Private Data

```js
const response = await session.authFetch('https://alice.pod/private/notes.ttl')
const data = await response.text()
```

### Write to Pod

```js
await session.authFetch('https://alice.pod/public/hello.txt', {
  method: 'PUT',
  headers: { 'Content-Type': 'text/plain' },
  body: 'Hello, Solid!'
})
```

### Multiple Identity Providers

```js
const providers = [
  'https://solidcommunity.net',
  'https://solidweb.org',
  'https://login.inrupt.com'
]
await session.login(providers[0], window.location.href)
```

## Installation

```js
// CDN (recommended)
import { Session } from 'https://esm.sh/gh/JavaScriptSolidServer/solid-oidc/solid-oidc.js'

// npm
import { Session } from 'solid-oidc'

// Local copy
import { Session } from './solid-oidc.js'
```

## Browser Requirements

| Requirement | Notes |
|-------------|-------|
| ES Modules | `<script type="module">` |
| `crypto.subtle` | Requires HTTPS or localhost |
| `indexedDB` | Session persistence |

## Specifications

| Spec | Description |
|------|-------------|
| [Solid-OIDC](https://solidproject.org/TR/oidc) | Solid authentication |
| [RFC 6749](https://tools.ietf.org/html/rfc6749) | OAuth 2.0 |
| [RFC 7636](https://tools.ietf.org/html/rfc7636) | PKCE |
| [RFC 7638](https://tools.ietf.org/html/rfc7638) | JWK Thumbprint |
| [RFC 9207](https://tools.ietf.org/html/rfc9207) | Authorization Server Issuer Identification |
| [RFC 9449](https://tools.ietf.org/html/rfc9449) | DPoP |

## License

AGPL-3.0
