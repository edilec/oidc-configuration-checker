/**
 * URI shapes: what a redirect URI may look like, and what an OpenID Provider
 * endpoint may look like.
 *
 * Two different questions, deliberately answered by two different functions.
 * A provider endpoint is a web URL the provider itself serves and it must be
 * `https`. A redirect URI is a destination the user agent is sent back to, and
 * RFC 8252 makes two exceptions for applications that have no web origin at
 * all: a loopback `http` URI and a private-use scheme of the application's own
 * reverse-domain name. Refusing those would be a false refusal, and a check
 * that rejects legitimate configuration is a defect exactly as much as one that
 * accepts dangerous configuration.
 *
 * Nothing here matches a URI against a pattern. Every comparison this package
 * makes between a URI and a policy is a comparison of two exact strings, which
 * is the whole point: prefix and wildcard matching is how an authorization
 * response ends up delivered to somebody else's host.
 */

import { MAX_URI_LENGTH, hasForbiddenCharacter } from './text.mjs'

/** Loopback hosts RFC 8252 permits for a native application's redirect URI. */
const LOOPBACK_LITERALS = Object.freeze(['127.0.0.1', '[::1]'])

/**
 * Inspect a redirect URI.
 *
 * Returns `{ ok: false, reason }` when the value is not a URI this tool can
 * reason about at all -- the caller then refuses the entry and the run is
 * incomplete, because a URI nobody parsed is not a URI anybody checked.
 * Returns `{ ok: true, url, notes }` otherwise, where `notes` names every
 * property the caller turns into a finding. The value itself is never judged
 * against a pattern and never rewritten.
 */
export function inspectRedirectUri(value) {
  if (typeof value !== 'string') return { ok: false, reason: 'not-a-string' }
  if (value.length === 0) return { ok: false, reason: 'empty' }
  if (value.length > MAX_URI_LENGTH) return { ok: false, reason: 'too-long' }
  if (hasForbiddenCharacter(value)) return { ok: false, reason: 'forbidden-character' }
  if (/\s/.test(value)) return { ok: false, reason: 'whitespace' }
  // Checked on the raw string, before parsing. `new URL` percent-encodes or
  // relocates a `*` depending on where it sits, so asking the parsed URL
  // whether it holds a wildcard answers a different question than the one a
  // reviewer is asking about the registered value.
  if (value.includes('*')) return { ok: false, reason: 'wildcard' }

  let url
  try {
    url = new URL(value)
  } catch {
    return { ok: false, reason: 'not-absolute' }
  }

  const notes = []
  // Asked of the raw string rather than of `url.hash`: a URI ending in a bare
  // `#` parses to an empty hash, and an empty fragment is still a fragment the
  // provider must refuse to register.
  if (value.includes('#')) notes.push('fragment')
  if (url.username !== '' || url.password !== '') notes.push('userinfo')

  if (url.protocol === 'https:') return { ok: true, url, notes }
  if (url.protocol === 'http:') {
    if (LOOPBACK_LITERALS.includes(url.hostname)) return { ok: true, url, notes }
    if (url.hostname === 'localhost') {
      notes.push('loopback-hostname')
      return { ok: true, url, notes }
    }
    notes.push('insecure-scheme')
    return { ok: true, url, notes }
  }
  // A private-use scheme is a reverse-domain name: `com.example.app:/callback`.
  // RFC 8252 section 7.1 recommends exactly this for a native application, and
  // the dot is what distinguishes it from `javascript:`, `data:` or a bare
  // `myapp:` that any other installed application may also claim.
  if (/^[a-z][a-z0-9+.-]*:$/.test(url.protocol) && url.protocol.slice(0, -1).includes('.')) {
    return { ok: true, url, notes }
  }
  notes.push('insecure-scheme')
  return { ok: true, url, notes }
}

/**
 * Inspect an OpenID Provider endpoint or issuer URL.
 *
 * `https` with no fragment; a query string is allowed on an endpoint and
 * refused on an issuer, which is the caller's distinction to draw. The issuer
 * rules come from OpenID Connect Discovery: the issuer is compared byte for
 * byte against the `iss` claim, so it carries no query and no fragment and its
 * trailing slash is part of it.
 */
export function inspectEndpoint(value) {
  if (typeof value !== 'string') return { ok: false, reason: 'not-a-string' }
  if (value.length === 0) return { ok: false, reason: 'empty' }
  if (value.length > MAX_URI_LENGTH) return { ok: false, reason: 'too-long' }
  if (hasForbiddenCharacter(value)) return { ok: false, reason: 'forbidden-character' }
  if (/\s/.test(value)) return { ok: false, reason: 'whitespace' }

  let url
  try {
    url = new URL(value)
  } catch {
    return { ok: false, reason: 'not-absolute' }
  }

  return {
    ok: true,
    url,
    https: url.protocol === 'https:',
    hasQuery: value.includes('?'),
    hasFragment: value.includes('#'),
    origin: `${url.protocol}//${url.host}`,
  }
}
