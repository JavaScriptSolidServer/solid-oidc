/**
 * solid-oidc.js - Minimal Solid-OIDC client for browsers
 *
 * A zero-build, zero-dependency, single-file Solid-OIDC authentication library.
 *
 * @license AGPL-3.0-or-later
 * @author Melvin Carvalho
 * @see https://github.com/JavaScriptSolidServer/solid-oidc
 *
 * Based on solid-oidc-client-browser by uvdsl (Christoph Braun)
 * @see https://github.com/uvdsl/solid-oidc-client-browser
 *
 * Implements:
 * - RFC 6749 - OAuth 2.0
 * - RFC 7636 - PKCE
 * - RFC 7638 - JWK Thumbprint
 * - RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification
 * - RFC 9449 - DPoP (Demonstration of Proof-of-Possession)
 * - Solid-OIDC Specification
 */

// ============================================================================
// Base64url Helpers
// ============================================================================

function base64urlEncode(data) {
  if (data instanceof ArrayBuffer) data = new Uint8Array(data)
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/')
  while (str.length % 4) str += '='
  return Uint8Array.from(atob(str), c => c.charCodeAt(0))
}

// ============================================================================
// URL Helpers
// ============================================================================

// Normalize URLs by trimming a single trailing slash, so iss/issuer
// comparisons survive trailing-slash variance between OIDC discovery doc,
// redirect `iss` parameter, and token `iss` claim. RFC 9207 §2.3 requires
// comparison after normalization.
const trimSlash = (s) => (typeof s === 'string' && s.endsWith('/')) ? s.slice(0, -1) : s

// ============================================================================
// Web Crypto JWT Helpers (replaces jose dependency)
// ============================================================================

function decodeJwt(token) {
  const parts = token.split('.')
  if (parts.length !== 3) throw new Error('Invalid JWT')
  return JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1])))
}

async function signJWT(payload, privateKey, protectedHeader) {
  const header = base64urlEncode(new TextEncoder().encode(JSON.stringify(protectedHeader)))
  const body = base64urlEncode(new TextEncoder().encode(JSON.stringify(payload)))
  const signingInput = new TextEncoder().encode(`${header}.${body}`)

  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    privateKey,
    signingInput
  )

  return `${header}.${body}.${base64urlEncode(signature)}`
}

function getImportAlgorithm(alg) {
  const algorithms = {
    ES256: { name: 'ECDSA', namedCurve: 'P-256' },
    ES384: { name: 'ECDSA', namedCurve: 'P-384' },
    RS256: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
    RS384: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-384' } },
    RS512: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-512' } },
    PS256: { name: 'RSA-PSS', hash: { name: 'SHA-256' } },
    PS384: { name: 'RSA-PSS', hash: { name: 'SHA-384' } },
    PS512: { name: 'RSA-PSS', hash: { name: 'SHA-512' } }
  }
  if (!algorithms[alg]) throw new Error(`Unsupported algorithm: ${alg}`)
  return algorithms[alg]
}

function getVerifyAlgorithm(alg) {
  if (alg.startsWith('ES')) return { name: 'ECDSA', hash: { name: `SHA-${alg.slice(2)}` } }
  if (alg.startsWith('RS')) return { name: 'RSASSA-PKCS1-v1_5' }
  if (alg.startsWith('PS')) return { name: 'RSA-PSS', saltLength: parseInt(alg.slice(2)) / 8 }
  throw new Error(`Unsupported algorithm: ${alg}`)
}

async function verifyJWT(token, jwksUri, options = {}) {
  const parts = token.split('.')
  if (parts.length !== 3) throw new Error('Invalid JWT')

  const header = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[0])))
  const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1])))

  if (options.issuer && trimSlash(payload.iss) !== trimSlash(options.issuer)) {
    throw new Error(`Issuer mismatch: ${payload.iss} !== ${options.issuer}`)
  }
  if (options.audience) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
    if (!aud.includes(options.audience)) throw new Error('Audience mismatch')
  }

  // Time-based claims (exp, nbf) with 60s clock skew tolerance
  const now = Math.floor(Date.now() / 1000)
  const skew = 60
  if (typeof payload.exp === 'number' && now - skew > payload.exp) {
    throw new Error('Token expired')
  }
  if (typeof payload.nbf === 'number' && now + skew < payload.nbf) {
    throw new Error('Token not yet valid')
  }

  // Fetch JWKS and find matching key
  const response = await fetch(jwksUri)
  if (!response.ok) throw new Error(`JWKS fetch failed: ${response.status}`)
  const jwks = await response.json()

  const jwk = header.kid
    ? jwks.keys.find(k => k.kid === header.kid)
    : jwks.keys.find(k => k.alg === header.alg || (!k.alg && (!k.use || k.use === 'sig')))
  if (!jwk) throw new Error('No matching key found in JWKS')

  const publicKey = await crypto.subtle.importKey(
    'jwk', jwk, getImportAlgorithm(header.alg), false, ['verify']
  )

  const valid = await crypto.subtle.verify(
    getVerifyAlgorithm(header.alg),
    publicKey,
    base64urlDecode(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  )
  if (!valid) throw new Error('Invalid signature')

  return { payload, protectedHeader: header }
}

/** JWK Thumbprint per RFC 7638 */
async function calculateJwkThumbprint(jwk) {
  // Required members in lexicographic order per key type
  let thumbprintInput
  if (jwk.kty === 'EC') {
    thumbprintInput = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
  } else if (jwk.kty === 'RSA') {
    thumbprintInput = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })
  } else {
    throw new Error(`Unsupported key type: ${jwk.kty}`)
  }
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(thumbprintInput))
  return base64urlEncode(digest)
}

// ============================================================================
// Session Events
// ============================================================================

export const SessionEvents = {
  STATE_CHANGE: 'sessionStateChange',
  EXPIRATION_WARNING: 'sessionExpirationWarning',
  EXPIRATION: 'sessionExpiration'
}

// ============================================================================
// Session Database Interface (IndexedDB Implementation)
// ============================================================================

export class SessionDatabase {
  constructor(dbName = 'solid-oidc', storeName = 'session', dbVersion = 1) {
    this.dbName = dbName
    this.storeName = storeName
    this.dbVersion = dbVersion
    this.db = null
  }

  async init() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.dbVersion)
      request.onerror = () => reject(new Error(`Database error: ${request.error}`))
      request.onsuccess = () => {
        this.db = request.result
        resolve(this)
      }
      request.onupgradeneeded = (event) => {
        const db = event.target.result
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName)
        }
      }
    })
  }

  async setItem(id, value) {
    if (!this.db) await this.init()
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.storeName, 'readwrite')
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(new Error(`Transaction error: ${tx.error}`))
      tx.objectStore(this.storeName).put(value, id)
    })
  }

  async getItem(id) {
    if (!this.db) await this.init()
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.storeName, 'readonly')
      tx.onerror = () => reject(new Error(`Transaction error: ${tx.error}`))
      const request = tx.objectStore(this.storeName).get(id)
      request.onsuccess = () => resolve(request.result || null)
    })
  }

  async deleteItem(id) {
    if (!this.db) await this.init()
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.storeName, 'readwrite')
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(new Error(`Transaction error: ${tx.error}`))
      tx.objectStore(this.storeName).delete(id)
    })
  }

  async clear() {
    if (!this.db) await this.init()
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.storeName, 'readwrite')
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(new Error(`Transaction error: ${tx.error}`))
      tx.objectStore(this.storeName).clear()
    })
  }

  close() {
    if (this.db) {
      this.db.close()
      this.db = null
    }
  }
}

// ============================================================================
// PKCE Helper (RFC 7636)
// ============================================================================

async function generatePKCE() {
  const verifier = crypto.randomUUID() + '-' + crypto.randomUUID()
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  )
  const challenge = btoa(String.fromCharCode(...digest))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
  return { verifier, challenge }
}

// ============================================================================
// DPoP Helper (RFC 9449)
// ============================================================================

async function createDPoPToken(keyPair, htu, htm, ath = null) {
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  // Strip non-required fields for cleaner header
  const jwk = { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y }

  const payload = {
    htu,
    htm,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID()
  }
  if (ath) payload.ath = ath

  return signJWT(payload, keyPair.privateKey, { alg: 'ES256', typ: 'dpop+jwt', jwk })
}

async function computeAth(accessToken) {
  const data = new TextEncoder().encode(accessToken)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return btoa(String.fromCharCode(...hashArray))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

// ============================================================================
// OIDC Discovery
// ============================================================================

async function discoverOIDC(idp) {
  const origin = new URL(idp).origin
  const response = await fetch(`${origin}/.well-known/openid-configuration`)
  if (!response.ok) throw new Error(`OIDC discovery failed: ${response.status}`)
  return response.json()
}

// ============================================================================
// Dynamic Client Registration
// ============================================================================

async function registerClient(registrationEndpoint, redirectUris) {
  const response = await fetch(registrationEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      application_type: 'web',
      redirect_uris: redirectUris,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: 'openid offline_access webid'
    })
  })
  if (!response.ok) throw new Error(`Client registration failed: ${response.status}`)
  return response.json()
}

// ============================================================================
// Token Request
// ============================================================================

async function requestTokens(tokenEndpoint, params, keyPair) {
  const dpop = await createDPoPToken(keyPair, tokenEndpoint, 'POST')
  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'DPoP': dpop
    },
    body: new URLSearchParams(params)
  })
  if (!response.ok) throw new Error(`Token request failed: ${response.status}`)
  return response.json()
}

// ============================================================================
// Token Validation
// ============================================================================

async function validateAccessToken(accessToken, jwksUri, issuer, clientId, keyPair) {
  const { payload } = await verifyJWT(accessToken, jwksUri, {
    issuer,
    audience: 'solid'
  })

  // Verify DPoP binding
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  const thumbprint = await calculateJwkThumbprint(publicJwk)
  if (payload.cnf?.jkt !== thumbprint) {
    throw new Error('DPoP thumbprint mismatch')
  }

  // Verify client_id
  if (payload.client_id !== clientId) {
    throw new Error('client_id mismatch')
  }

  return payload
}

// ============================================================================
// Refresh Token Grant
// ============================================================================

async function refreshTokens(database) {
  await database.init()

  const [refreshToken, tokenEndpoint, clientId, keyPair] = await Promise.all([
    database.getItem('refresh_token'),
    database.getItem('token_endpoint'),
    database.getItem('client_id'),
    database.getItem('dpop_keypair')
  ])

  if (!refreshToken || !tokenEndpoint || !clientId || !keyPair) {
    throw new Error('Missing refresh data')
  }

  const tokens = await requestTokens(tokenEndpoint, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId
  }, keyPair)

  // Persist new refresh token if provided
  if (tokens.refresh_token) {
    await database.setItem('refresh_token', tokens.refresh_token)
  }

  database.close()
  return { ...tokens, dpop_key_pair: keyPair }
}

// ============================================================================
// Main Session Class
// ============================================================================

export class Session extends EventTarget {
  constructor(options = {}) {
    super()
    this.clientId = options.clientId || null
    this.database = options.database || new SessionDatabase()
    this.onStateChange = options.onStateChange || null
    this.onExpirationWarning = options.onExpirationWarning || null
    this.onExpiration = options.onExpiration || null

    // Internal state
    this._isActive = false
    this._webId = null
    this._exp = null
    this._ath = null
    this._tokens = null
    this._idpDetails = null
    this._refreshPromise = null

    // Set up event listeners
    if (this.onStateChange) {
      this.addEventListener(SessionEvents.STATE_CHANGE, this.onStateChange)
    }
    if (this.onExpirationWarning) {
      this.addEventListener(SessionEvents.EXPIRATION_WARNING, this.onExpirationWarning)
    }
    if (this.onExpiration) {
      this.addEventListener(SessionEvents.EXPIRATION, this.onExpiration)
    }
  }

  // ==========================================================================
  // Public API
  // ==========================================================================

  get isActive() { return this._isActive }
  get webId() { return this._webId }

  isExpired() {
    if (!this._exp) return true
    return Math.floor(Date.now() / 1000) >= this._exp
  }

  getExpiresIn() {
    if (!this._exp) return -1
    return this._exp - Math.floor(Date.now() / 1000)
  }

  /**
   * Redirect user to identity provider for login
   */
  async login(idp, redirectUri) {
    // Sanitize redirect URI (RFC 6749 Section 3.1.2)
    const redirectUrl = new URL(redirectUri)
    const sanitizedRedirect = redirectUrl.origin + redirectUrl.pathname + redirectUrl.search

    // OIDC Discovery
    const config = await discoverOIDC(idp)

    // RFC 9207: Verify issuer
    const issuer = config.issuer
    if (trimSlash(idp) !== trimSlash(issuer)) {
      throw new Error(`Issuer mismatch: ${issuer} !== ${idp}`)
    }

    // Store IDP details
    sessionStorage.setItem('solid_oidc_idp', issuer)
    sessionStorage.setItem('solid_oidc_token_endpoint', config.token_endpoint)
    sessionStorage.setItem('solid_oidc_jwks_uri', config.jwks_uri)

    // Get or register client_id
    let clientId = this.clientId
    if (!clientId) {
      const registration = await registerClient(config.registration_endpoint, [sanitizedRedirect])
      clientId = registration.client_id
      sessionStorage.setItem('solid_oidc_client_id', clientId)
    }

    // PKCE (RFC 7636)
    const pkce = await generatePKCE()
    sessionStorage.setItem('solid_oidc_pkce_verifier', pkce.verifier)

    // CSRF token
    const csrfToken = crypto.randomUUID()
    sessionStorage.setItem('solid_oidc_csrf', csrfToken)

    // Build authorization URL
    const authUrl = new URL(config.authorization_endpoint)
    authUrl.searchParams.set('response_type', 'code')
    authUrl.searchParams.set('redirect_uri', sanitizedRedirect)
    authUrl.searchParams.set('scope', 'openid offline_access webid')
    authUrl.searchParams.set('client_id', clientId)
    authUrl.searchParams.set('code_challenge_method', 'S256')
    authUrl.searchParams.set('code_challenge', pkce.challenge)
    authUrl.searchParams.set('state', csrfToken)
    authUrl.searchParams.set('prompt', 'consent')

    // Redirect to IDP
    window.location.href = authUrl.toString()
  }

  /**
   * Handle redirect from identity provider after login
   */
  async handleRedirectFromLogin() {
    const url = new URL(window.location.href)
    const code = url.searchParams.get('code')

    // No code = not a redirect, nothing to do
    if (!code) return

    // RFC 9207: Verify issuer
    const idp = sessionStorage.getItem('solid_oidc_idp')
    const iss = url.searchParams.get('iss')
    if (!idp || trimSlash(iss) !== trimSlash(idp)) {
      throw new Error(`Issuer mismatch: ${iss} !== ${idp}`)
    }

    // RFC 6749: Verify CSRF token
    const csrf = sessionStorage.getItem('solid_oidc_csrf')
    if (url.searchParams.get('state') !== csrf) {
      throw new Error('CSRF token mismatch')
    }

    // Clean URL
    url.searchParams.delete('code')
    url.searchParams.delete('iss')
    url.searchParams.delete('state')
    window.history.replaceState({}, document.title, url.toString())

    // Get stored values
    const pkceVerifier = sessionStorage.getItem('solid_oidc_pkce_verifier')
    const tokenEndpoint = sessionStorage.getItem('solid_oidc_token_endpoint')
    const jwksUri = sessionStorage.getItem('solid_oidc_jwks_uri')
    const clientId = this.clientId || sessionStorage.getItem('solid_oidc_client_id')

    if (!pkceVerifier || !tokenEndpoint || !clientId) {
      throw new Error('Missing session data')
    }

    // Generate DPoP key pair (ES256 / P-256)
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    )

    // Exchange code for tokens
    const tokens = await requestTokens(tokenEndpoint, {
      grant_type: 'authorization_code',
      code,
      code_verifier: pkceVerifier,
      redirect_uri: url.origin + url.pathname,
      client_id: clientId
    }, keyPair)

    // Validate access token
    await validateAccessToken(tokens.access_token, jwksUri, idp, clientId, keyPair)

    // Store IDP details
    this._idpDetails = { idp, jwksUri, tokenEndpoint }

    // Persist for refresh
    await this.database.init()
    await Promise.all([
      this.database.setItem('idp', idp),
      this.database.setItem('jwks_uri', jwksUri),
      this.database.setItem('token_endpoint', tokenEndpoint),
      this.database.setItem('client_id', clientId),
      this.database.setItem('dpop_keypair', keyPair),
      this.database.setItem('refresh_token', tokens.refresh_token)
    ])
    this.database.close()

    // Clean session storage
    sessionStorage.removeItem('solid_oidc_idp')
    sessionStorage.removeItem('solid_oidc_token_endpoint')
    sessionStorage.removeItem('solid_oidc_jwks_uri')
    sessionStorage.removeItem('solid_oidc_client_id')
    sessionStorage.removeItem('solid_oidc_pkce_verifier')
    sessionStorage.removeItem('solid_oidc_csrf')

    // Update session state
    await this._setTokens({ ...tokens, dpop_key_pair: keyPair })
    this._dispatchStateChange()
  }

  /**
   * Restore session using stored refresh token
   */
  async restore() {
    if (this._refreshPromise) return this._refreshPromise

    this._refreshPromise = (async () => {
      try {
        const tokens = await refreshTokens(this.database)
        await this._setTokens(tokens)
        this._dispatchStateChange()
      } catch (error) {
        if (this._isActive) {
          if (!this.isExpired()) {
            this._dispatchExpirationWarning()
          } else {
            this._dispatchExpiration()
          }
        }
        throw error
      } finally {
        this._refreshPromise = null
      }
    })()

    return this._refreshPromise
  }

  /**
   * Log out and clear all session data
   */
  async logout() {
    this._isActive = false
    this._webId = null
    this._exp = null
    this._ath = null
    this._tokens = null
    this._idpDetails = null

    await this.database.init()
    await this.database.clear()
    this.database.close()

    this._dispatchStateChange()
  }

  /**
   * Make authenticated fetch request with DPoP
   */
  async authFetch(input, init = {}) {
    // No session = regular fetch
    if (!this._isActive) {
      return fetch(input, init)
    }

    // Refresh if expired
    if (this.isExpired()) {
      await this.restore()
    }

    // Parse request
    let url, method, headers
    if (input instanceof Request) {
      url = new URL(input.url)
      method = init.method || input.method || 'GET'
      headers = new Headers(input.headers)
    } else {
      url = new URL(input.toString())
      method = init.method || 'GET'
      headers = init.headers ? new Headers(init.headers) : new Headers()
    }

    // Create DPoP proof
    const dpop = await createDPoPToken(
      this._tokens.dpop_key_pair,
      `${url.origin}${url.pathname}`,
      method.toUpperCase(),
      this._ath
    )

    // Set auth headers
    headers.set('DPoP', dpop)
    headers.set('Authorization', `DPoP ${this._tokens.access_token}`)

    // Make request
    if (input instanceof Request) {
      return fetch(new Request(input, { ...init, headers }))
    }
    return fetch(url, { ...init, headers })
  }

  // ==========================================================================
  // Internal Methods
  // ==========================================================================

  async _setTokens(tokens) {
    this._tokens = tokens

    const decoded = decodeJwt(tokens.access_token)
    if (!decoded.webid) throw new Error('Missing webid claim')
    if (!decoded.exp) throw new Error('Missing exp claim')

    this._ath = await computeAth(tokens.access_token)
    this._webId = decoded.webid
    this._exp = decoded.exp
    this._isActive = true
  }

  _dispatchStateChange() {
    this.dispatchEvent(new CustomEvent(SessionEvents.STATE_CHANGE, {
      detail: { isActive: this._isActive, webId: this._webId }
    }))
  }

  _dispatchExpirationWarning() {
    this.dispatchEvent(new CustomEvent(SessionEvents.EXPIRATION_WARNING, {
      detail: { expires_in: this.getExpiresIn() }
    }))
  }

  _dispatchExpiration() {
    this.dispatchEvent(new CustomEvent(SessionEvents.EXPIRATION))
  }
}

// ============================================================================
// Default Export
// ============================================================================

export default Session
