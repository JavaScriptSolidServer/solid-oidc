# solid-oidc

[![npm version](https://img.shields.io/npm/v/solid-oidc.svg)](https://www.npmjs.com/package/solid-oidc)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

**Minimal, zero-build Solid-OIDC client for browsers.**

A single JavaScript file (~600 lines) that handles the complete Solid-OIDC authentication flow. No bundler, no transpiler, no build step required.

[**Live Demo**](https://javascriptsolidserver.github.io/solid-oidc/example.html) · [**API Reference**](#api-reference) · [**Examples**](#advanced-usage)

---

## Why solid-oidc?

| Feature | solid-oidc | Other libraries |
|---------|------------|-----------------|
| **Size** | ~600 lines | 5,000+ lines |
| **Build step** | None | Required |
| **Copy-paste ready** | Yes | No |
| **Readable source** | Yes | Compiled/minified |

## Features

- **Zero build step** — Import from CDN or copy the file
- **Single file** — One `solid-oidc.js`, nothing else
- **~600 lines** — Readable, auditable, hackable
- **Full Solid-OIDC** — Login, logout, token refresh, authenticated fetch
- **DPoP bound tokens** — Secure proof-of-possession (RFC 9449)
- **Persistent sessions** — Survives page refresh via IndexedDB
- **Event-driven** — React to session state changes

---

## Quick Start

```html
<!DOCTYPE html>
<html>
<head>
  <title>Solid App</title>
</head>
<body>
  <button id="login">Login</button>
  <button id="logout" hidden>Logout</button>
  <pre id="output"></pre>

  <script type="module">
    import { Session } from 'https://esm.sh/gh/JavaScriptSolidServer/solid-oidc/solid-oidc.js'

    const session = new Session({
      onStateChange: (e) => {
        document.getElementById('login').hidden = e.detail.isActive
        document.getElementById('logout').hidden = !e.detail.isActive
        document.getElementById('output').textContent = e.detail.isActive
          ? `Logged in as ${e.detail.webId}`
          : 'Not logged in'
      }
    })

    // Try to restore previous session
    session.restore().catch(() => {})

    // Handle redirect from identity provider
    session.handleRedirectFromLogin()

    // Login button
    document.getElementById('login').onclick = () => {
      session.login('https://solidcommunity.net', window.location.href)
    }

    // Logout button
    document.getElementById('logout').onclick = () => {
      session.logout()
    }
  </script>
</body>
</html>
```

**That's it.** No npm install, no webpack, no configuration.

---

## Installation

### Option 1: CDN (Recommended)

```js
import { Session } from 'https://esm.sh/gh/JavaScriptSolidServer/solid-oidc/solid-oidc.js'
```

### Option 2: npm

```bash
npm install solid-oidc
```

```js
import { Session } from 'solid-oidc'
```

### Option 3: Copy the file

Download [`solid-oidc.js`](solid-oidc.js) and import it directly:

```js
import { Session } from './solid-oidc.js'
```

---

## API Reference

### `new Session(options)`

Create a new session instance.

```js
const session = new Session({
  // Optional: Pre-registered client_id (skips dynamic registration)
  clientId: 'https://myapp.example/id',

  // Optional: Custom database for session persistence
  database: new SessionDatabase('my-app'),

  // Optional: Event callbacks
  onStateChange: (event) => console.log(event.detail),
  onExpirationWarning: (event) => console.log('Expiring in', event.detail.expires_in),
  onExpiration: () => console.log('Session expired')
})
```

### `session.login(idp, redirectUri)`

Redirect user to identity provider for authentication.

```js
await session.login('https://solidcommunity.net', window.location.href)
```

| Parameter | Description |
|-----------|-------------|
| `idp` | Identity provider URL (e.g., `https://solidcommunity.net`) |
| `redirectUri` | URL to redirect back to after login |

### `session.handleRedirectFromLogin()`

Handle the redirect from the identity provider. Call this on page load.

```js
await session.handleRedirectFromLogin()
```

### `session.restore()`

Restore a previous session using stored refresh token.

```js
try {
  await session.restore()
  console.log('Session restored')
} catch (error) {
  console.log('No session to restore')
}
```

### `session.logout()`

End the session and clear all stored data.

```js
await session.logout()
```

### `session.authFetch(url, options)`

Make an authenticated fetch request. Automatically includes DPoP proof and access token.

```js
const response = await session.authFetch('https://pod.example/private/data.ttl')
const data = await response.text()
```

Falls back to regular `fetch()` if no session is active.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `session.isActive` | `boolean` | Whether user is logged in |
| `session.webId` | `string \| null` | User's WebID when logged in |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `session.isExpired()` | `boolean` | Whether access token is expired |
| `session.getExpiresIn()` | `number` | Seconds until token expires (-1 if no token) |

### Events

The session extends `EventTarget` and emits these events:

| Event | Detail | Description |
|-------|--------|-------------|
| `sessionStateChange` | `{ isActive, webId }` | Login/logout occurred |
| `sessionExpirationWarning` | `{ expires_in }` | Token refresh failed but not expired |
| `sessionExpiration` | — | Token expired and refresh failed |

```js
session.addEventListener('sessionStateChange', (event) => {
  console.log('Active:', event.detail.isActive)
  console.log('WebID:', event.detail.webId)
})
```

---

## Advanced Usage

### Custom Session Database

```js
import { Session, SessionDatabase } from './solid-oidc.js'

// Use a custom database name (useful for multiple sessions)
const database = new SessionDatabase('my-app-session')
const session = new Session({ database })
```

### Pre-registered Client ID

Skip dynamic registration by providing your client ID:

```js
const session = new Session({
  clientId: 'https://myapp.example/id'
})
```

### Multiple Identity Providers

```js
const providers = [
  { name: 'Solid Community', url: 'https://solidcommunity.net' },
  { name: 'solidweb.org', url: 'https://solidweb.org' },
  { name: 'solidweb.me', url: 'https://solidweb.me' }
]

// Let user choose
const idp = prompt('Choose provider:', providers[0].url)
await session.login(idp, window.location.href)
```

### Handling Token Expiration

```js
const session = new Session({
  onExpirationWarning: async (event) => {
    console.log(`Token expires in ${event.detail.expires_in}s, refreshing...`)
    try {
      await session.restore()
    } catch {
      if (confirm('Session expired. Login again?')) {
        await session.login(idp, window.location.href)
      }
    }
  }
})
```

---

## Specifications

This library implements:

| Specification | Description |
|---------------|-------------|
| [RFC 6749](https://tools.ietf.org/html/rfc6749) | OAuth 2.0 |
| [RFC 7636](https://tools.ietf.org/html/rfc7636) | PKCE |
| [RFC 9207](https://tools.ietf.org/html/rfc9207) | Authorization Server Issuer Identification |
| [RFC 9449](https://tools.ietf.org/html/rfc9449) | DPoP (Demonstration of Proof-of-Possession) |
| [Solid-OIDC](https://solidproject.org/TR/oidc) | Solid OIDC Specification |

---

## Testing

Open [`test.html`](test.html) in a browser to run the test suite:

```bash
npx serve .
# Visit http://localhost:3000/test.html
```

Tests cover:
- Session instantiation and state management
- SessionDatabase (IndexedDB) operations
- Event dispatching

---

## Browser Support

| Requirement | Notes |
|-------------|-------|
| ES Modules | `<script type="module">` |
| `crypto.subtle` | Requires HTTPS or localhost |
| `indexedDB` | For session persistence |

**Supported browsers:** Chrome 63+, Firefox 57+, Safari 11+, Edge 79+

---

## Credits

Based on [solid-oidc-client-browser](https://github.com/uvdsl/solid-oidc-client-browser) by [uvdsl (Christoph Braun)](https://github.com/uvdsl). Refactored into a minimal, zero-build, single-file library.

## License

[MIT](LICENSE)
