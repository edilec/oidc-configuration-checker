/**
 * The checks themselves: issuer alignment, endpoint transport, redirect policy,
 * algorithm policy and key-set rotation readiness.
 *
 * Every conclusion drawn here is a conclusion about four local files. Nothing in
 * this module contacts an issuer, requests a token, decodes a token, or
 * attempts an authorization flow -- see the README for the list of things this
 * tool deliberately does not do and could not do if it wanted to.
 *
 * Two habits run through all of it:
 *
 * - **Unknown is recorded as unknown.** An algorithm this build does not
 *   implement, a key type it cannot inspect, a URI it could not parse: each
 *   leaves the thing it belongs to out of every "satisfied" set and marks the
 *   run incomplete. A key whose algorithm nobody here implements is unsupported,
 *   which is not approved.
 * - **Comparison is exact.** A redirect URI is compared to the policy as one
 *   string against another. No prefix, no wildcard, no normalisation, no case
 *   folding. Prefix matching is how an authorization response ends up delivered
 *   to a host the deployment never registered, and a checker that mirrors the
 *   loose behaviour cannot detect it.
 */

import { createHash } from 'node:crypto'

import {
  KEY_TYPES,
  KEY_USES,
  KNOWN_KEY_MEMBERS,
  NONE_ALGORITHM,
  PRIVATE_PARAMETERS,
  classifyAlgorithm,
  coordinateBytesFor,
  inspectKeyMaterial,
  privateParametersIn,
} from './algorithms.mjs'
import { byCodeUnit, describeValue, excerpt, isIdentifier, isToken } from './text.mjs'
import { inspectEndpoint, inspectRedirectUri } from './uri.mjs'

/** The one redirect matching mode this tool will call satisfied. */
export const EXACT_MATCHING = 'exact'

/** The code challenge method this tool will call satisfied when PKCE is required. */
export const REQUIRED_PKCE_METHOD = 'S256'

/**
 * Why a redirect URI could not be read, and what to say about it.
 *
 * The value is never reproduced: a refused URI is arbitrary text from a file
 * this tool did not write, and the pointer already says exactly where it is.
 */
const URI_REASONS = Object.freeze({
  empty: 'is an empty string',
  'forbidden-character': 'carries a control, separator or bidi character, so it would print as something other than the value that was registered',
  'not-a-string': 'is not a string',
  'not-absolute': 'is not an absolute URI with a scheme',
  'too-long': 'is longer than this build reads',
  whitespace: 'contains whitespace',
})

const NOTE_RULES = Object.freeze({
  fragment: {
    ruleId: 'redirect-uri-fragment',
    message: 'carries a fragment component. A redirect URI is registered and compared without one, and the authorization response appends its own.',
    suggestion: 'Register the URI without the "#" part.',
  },
  'insecure-scheme': {
    ruleId: 'redirect-uri-insecure-scheme',
    message: 'does not use https. An authorization response carrying a code or a token travels to this URI; http exposes it to anything on the path.',
    suggestion: 'Use https, a loopback address for a native application, or a private-use scheme of the form com.example.app:/callback.',
  },
  'loopback-hostname': {
    ruleId: 'redirect-uri-loopback-hostname',
    message: 'uses the name "localhost" rather than a literal loopback address. RFC 8252 section 8.3 prefers 127.0.0.1 or [::1], because what "localhost" resolves to is decided by a resolver the application does not control.',
    suggestion: 'Register http://127.0.0.1:PORT/... instead.',
  },
  userinfo: {
    ruleId: 'redirect-uri-userinfo',
    message: 'carries a userinfo component before the host. That is the shape a reader misjudges: everything before the "@" is not the host.',
    suggestion: 'Remove the userinfo component.',
  },
})

/** Distinguish exact strings whose bounded, safe excerpts happen to collide. */
function firstRawDifference(left, right, leftName, rightName) {
  let offset = 0
  while (offset < left.length && offset < right.length && left.charCodeAt(offset) === right.charCodeAt(offset)) offset += 1
  const unit = (value) => offset === value.length
    ? 'end'
    : `U+${value.charCodeAt(offset).toString(16).toUpperCase().padStart(4, '0')}`
  return `raw UTF-16 offset ${offset}: ${leftName} ${unit(left)} vs ${rightName} ${unit(right)}`
}

function issuerEvidence(provider, expected) {
  const providerLabel = excerpt(provider, 60)
  const clientLabel = excerpt(expected, 60)
  const base = `provider ${providerLabel} vs client ${clientLabel}`
  return providerLabel === clientLabel
    ? `provider/client ${providerLabel}; ${firstRawDifference(provider, expected, 'provider', 'client')}`
    : base
}

/**
 * Compare the issuer the provider declares with the issuer the client expects.
 *
 * This is the confused-deputy check. An ID token is only meaningful relative to
 * the issuer that minted it, so a client configured to accept tokens from one
 * issuer while pointed at the discovery document of another will accept a token
 * that was never about it. The comparison is exact, byte for byte, as OpenID
 * Connect Core requires of the `iss` claim -- including the trailing slash,
 * which gets its own rule because it is the mismatch people argue about.
 */
function checkIssuer(sink, files, metadata, client) {
  const result = { issuer: null, expectedIssuer: null, matches: null, settings: 0, origin: null, incomplete: false }

  if (typeof metadata.issuer === 'string') {
    const inspected = inspectEndpoint(metadata.issuer)
    if (!inspected.ok) {
      if (inspected.reason === 'forbidden-character') result.incomplete = true
      sink.add({
        file: files.metadata,
        pointer: '/issuer',
        ruleId: 'issuer-invalid',
        message: `"issuer" ${URI_REASONS[inspected.reason] ?? 'could not be read as a URL'}, so nothing was compared against it.`,
      })
    } else {
      result.issuer = metadata.issuer
      result.origin = inspected.origin
      if (!inspected.https) {
        sink.add({
          file: files.metadata,
          pointer: '/issuer',
          ruleId: 'issuer-not-https',
          message: 'The issuer is not an https URL. An issuer identifier is the trust anchor for every ID token this client accepts; over http it is asserted by whoever is on the path.',
          evidence: excerpt(metadata.issuer, 120),
        })
      }
      if (inspected.hasQuery || inspected.hasFragment) {
        sink.add({
          file: files.metadata,
          pointer: '/issuer',
          ruleId: 'issuer-invalid',
          message: 'An issuer identifier carries no query and no fragment component (OpenID Connect Discovery 1.0, section 2); this one does.',
          evidence: excerpt(metadata.issuer, 120),
        })
      }
    }
  }

  if (typeof client.expectedIssuer === 'string') {
    const inspected = inspectEndpoint(client.expectedIssuer)
    if (!inspected.ok) {
      if (inspected.reason === 'forbidden-character') result.incomplete = true
      sink.add({
        file: files.client,
        pointer: '/expectedIssuer',
        ruleId: 'issuer-invalid',
        message: `"expectedIssuer" ${URI_REASONS[inspected.reason] ?? 'could not be read as a URL'}, so nothing was compared against it.`,
      })
    } else result.expectedIssuer = client.expectedIssuer
  }

  if (result.issuer === null || result.expectedIssuer === null) return result

  result.settings = 1
  if (result.issuer === result.expectedIssuer) {
    result.matches = true
    return result
  }
  result.matches = false

  const trimmed = (value) => (value.endsWith('/') ? value.slice(0, -1) : value)
  if (trimmed(result.issuer) === trimmed(result.expectedIssuer)) {
    sink.add({
      file: files.client,
      pointer: '/expectedIssuer',
      ruleId: 'issuer-trailing-slash',
      message: 'The client expects an issuer that differs from the one the provider declares only by a trailing slash. The "iss" claim is compared exactly, so this configuration rejects every token the provider issues -- or accepts tokens it should not, depending on which side is normalised.',
      evidence: issuerEvidence(result.issuer, result.expectedIssuer),
      suggestion: 'Copy the issuer out of the discovery document verbatim.',
    })
    return result
  }

  sink.add({
    file: files.client,
    pointer: '/expectedIssuer',
    ruleId: 'issuer-mismatch',
    message: 'The client expects a different issuer from the one this discovery document declares. A client pointed at one provider while trusting another will accept an ID token that was never about it.',
    evidence: issuerEvidence(result.issuer, result.expectedIssuer),
    suggestion: 'Point the client at the provider whose discovery document this is, or fetch the discovery document of the issuer the client expects.',
  })
  return result
}

/** Check every endpoint the provider declares for transport and origin. */
function checkEndpoints(sink, files, metadata, issuerOrigin, budget) {
  let evaluated = 0
  for (const endpoint of metadata.endpoints) {
    budget.check()
    evaluated += 1
    const inspected = inspectEndpoint(endpoint.value)
    if (!inspected.ok) {
      sink.add({
        file: files.metadata,
        pointer: `/${endpoint.field}`,
        ruleId: 'endpoint-invalid',
        message: `"${endpoint.field}" ${URI_REASONS[inspected.reason] ?? 'could not be read as a URL'}.`,
      })
      continue
    }
    if (!inspected.https) {
      sink.add({
        file: files.metadata,
        pointer: `/${endpoint.field}`,
        ruleId: 'endpoint-not-https',
        message: `"${endpoint.field}" is not an https URL. OpenID Connect requires TLS on every endpoint that carries an authorization code, a token or a key set.`,
        evidence: excerpt(endpoint.value, 120),
      })
    }
    if (issuerOrigin !== null && inspected.origin !== issuerOrigin) {
      sink.add({
        file: files.metadata,
        pointer: `/${endpoint.field}`,
        ruleId: 'endpoint-origin-differs',
        message: `"${endpoint.field}" is served from a different origin than the issuer. That is legitimate for some providers and is how a tampered discovery document redirects a relying party, so it is reported rather than judged.`,
        evidence: `issuer ${excerpt(issuerOrigin, 60)} vs endpoint ${excerpt(inspected.origin, 60)}`,
        suggestion: 'Confirm this origin is the provider you mean to talk to.',
      })
    }
  }
  return evaluated
}

/**
 * Read one list of redirect URIs into the set that is compared exactly.
 *
 * A refused entry never enters the set. It is reported, it is counted, and the
 * caller marks the run incomplete and withholds absence claims: an exact-match
 * relation computed over part of a list is not the relation the documents
 * describe.
 */
function readUriList(sink, file, field, raw, budget) {
  const usable = []
  const seen = new Set()
  let refused = 0

  for (let index = 0; index < raw.length; index += 1) {
    budget.check()
    const pointer = `/${field}/${index}`
    const inspected = inspectRedirectUri(raw[index])

    if (!inspected.ok) {
      refused += 1
      if (inspected.reason === 'wildcard') {
        sink.add({
          file,
          pointer,
          ruleId: 'redirect-uri-wildcard',
          message: 'This entry holds a "*". A wildcard only means anything under prefix or pattern matching, which is how an authorization response reaches a host nobody registered; this tool compares exact strings and refused to guess which hosts the pattern stands for.',
          suggestion: 'List every redirect URI the deployment actually uses.',
        })
      } else {
        sink.add({
          file,
          pointer,
          ruleId: 'redirect-uri-invalid',
          message: `This entry ${URI_REASONS[inspected.reason] ?? 'could not be read'}, so it was refused rather than compared.`,
        })
      }
      continue
    }

    const value = raw[index]
    for (const note of inspected.notes) {
      const rule = NOTE_RULES[note]
      sink.add({
        file,
        pointer,
        ruleId: rule.ruleId,
        message: `This redirect URI ${rule.message}`,
        evidence: excerpt(value, 120),
        suggestion: rule.suggestion,
      })
    }

    if (seen.has(value)) {
      sink.add({
        file,
        pointer,
        ruleId: 'redirect-uri-duplicate',
        message: 'This redirect URI is listed more than once. The repeat adds nothing and was counted once; a list that looks longer than it is hides how much surface the client really has.',
        evidence: excerpt(value, 120),
      })
      continue
    }
    seen.add(value)
    usable.push({ index, pointer, value })
  }

  return { usable, refused }
}

/**
 * Compare one client list against one policy allowlist, exactly.
 *
 * `allowlist` is a `Set` of strings and membership is `===`. A known match is
 * still known if another entry was refused, but absence is not known until
 * both lists are complete. No normalisation happens anywhere in here.
 */
function compareUriList(sink, files, field, policyField, entries, allowedEntries, allowlist, used, relationComplete) {
  const folded = new Map()
  for (const allowed of allowlist) folded.set(allowed.toLowerCase(), allowed)

  for (const entry of entries) {
    if (allowlist.has(entry.value)) {
      used.add(entry.value)
      entry.status = 'allowlisted'
      continue
    }
    if (!relationComplete) {
      entry.status = 'unknown'
      continue
    }
    entry.status = 'not-allowlisted'
    const near = folded.get(entry.value.toLowerCase())
    const sameExcerpt = allowedEntries.find((allowed) => excerpt(allowed.value, 120) === excerpt(entry.value, 120))
    sink.add({
      file: files.client,
      pointer: entry.pointer,
      ruleId: 'redirect-uri-not-allowlisted',
      message: `This redirect URI is not in the policy's "${policyField}" list. It is compared as one exact string against another, which is what stops a registration from covering a host the deployment never approved.`,
      evidence: sameExcerpt === undefined
        ? excerpt(entry.value, 120)
        : `client/policy ${excerpt(entry.value, 50)}; ${firstRawDifference(entry.value, sameExcerpt.value, 'client', 'policy')}`,
      suggestion: near === undefined
        ? `Add the URI to "${policyField}", or remove it from "${field}".`
        : 'The policy lists a URI that differs from this one only in letter case; an exact-match policy treats the two as different. Make them identical.',
    })
  }
}

/** The redirect half of the run: shape, policy mode, and the exact comparison. */
function checkRedirects(sink, files, client, policy, budget) {
  const result = {
    redirectUris: [],
    postLogoutUris: [],
    counts: { redirectUris: 0, postLogoutUris: 0 },
    refused: 0,
  }

  if (policy.redirectUriMatching !== null && policy.redirectUriMatching !== EXACT_MATCHING) {
    sink.add({
      file: files.policy,
      pointer: '/redirectUriMatching',
      ruleId: 'redirect-matching-not-exact',
      message: `The policy declares "${excerpt(policy.redirectUriMatching, 40)}" matching. This tool implements exact matching only; it recognizes known exact matches and does not infer absence from a partial list. Prefix and pattern matching can deliver an authorization response to a host nobody registered.`,
      suggestion: 'Set "redirectUriMatching" to "exact" and list every URI in full.',
    })
  }

  const SPECS = [
    { field: 'redirectUris', policyField: 'allowedRedirectUris', key: 'redirectUris' },
    { field: 'postLogoutRedirectUris', policyField: 'allowedPostLogoutRedirectUris', key: 'postLogoutUris' },
  ]

  for (const spec of SPECS) {
    const declared = client[spec.field]
    const allowed = policy[spec.policyField]
    if (declared === null || allowed === null) continue

    const clientSide = readUriList(sink, files.client, spec.field, declared, budget)
    const policySide = readUriList(sink, files.policy, spec.policyField, allowed, budget)
    result.refused += clientSide.refused + policySide.refused
    const relationComplete = clientSide.refused === 0 && policySide.refused === 0

    const allowlist = new Set(policySide.usable.map((entry) => entry.value))
    const used = new Set()
    compareUriList(sink, files, spec.field, spec.policyField, clientSide.usable, policySide.usable, allowlist, used, relationComplete)

    if (relationComplete) {
      for (const entry of policySide.usable) {
        if (used.has(entry.value)) continue
        const sameExcerpt = clientSide.usable.find((clientEntry) => excerpt(clientEntry.value, 120) === excerpt(entry.value, 120))
        sink.add({
          file: files.policy,
          pointer: entry.pointer,
          ruleId: 'redirect-uri-unused',
          message: 'The policy allows this redirect URI and this client registers no such URI. A spare entry is reported rather than refused: another client may use it, and this tool reads one client.',
          evidence: sameExcerpt === undefined
            ? excerpt(entry.value, 120)
            : `policy/client ${excerpt(entry.value, 50)}; ${firstRawDifference(entry.value, sameExcerpt.value, 'policy', 'client')}`,
        })
      }
    }

    result.counts[spec.key] = clientSide.usable.length
    result[spec.key] = clientSide.usable
      .map((entry) => ({
        uri: excerpt(entry.value, 200),
        status: entry.status,
        ...(entry.value.length > 200
          ? { rawSha256: createHash('sha256').update(entry.value, 'utf16le').digest('hex') }
          : {}),
      }))
      .sort((left, right) => byCodeUnit(left.uri, right.uri))
  }

  return result
}

/** Algorithm policy, response types, authentication method and PKCE. */
function checkSettings(sink, files, metadata, client, policy, budget) {
  const result = {
    algorithms: { selected: null, offered: [], permitted: [] },
    selected: null,
    settings: 0,
    unknown: false,
  }

  const permitted = policy.allowedIdTokenSigningAlgs
  const offered = metadata.lists.idTokenAlgs

  if (permitted !== null) {
    result.algorithms.permitted = permitted.slice().sort(byCodeUnit)
    for (let index = 0; index < permitted.length; index += 1) {
      budget.check()
      const name = permitted[index]
      if (name === NONE_ALGORITHM) {
        sink.add({
          file: files.policy,
          pointer: `/allowedIdTokenSigningAlgs/${index}`,
          ruleId: 'alg-none-permitted',
          message: 'The policy permits "none". An ID token signed with "none" is not signed; permitting it makes every other check in this report beside the point. This tool refuses "none" whatever a policy says.',
          suggestion: 'Remove "none" from the permitted algorithms.',
        })
        continue
      }
      if (classifyAlgorithm(name).kind === 'unrecognised') {
        result.unknown = true
        sink.add({
          file: files.policy,
          pointer: `/allowedIdTokenSigningAlgs/${index}`,
          ruleId: 'alg-unrecognised',
          message: `The policy permits "${excerpt(name, 40)}", which this build does not implement. It was not treated as permitted and it was not treated as refused; a key or a client setting naming it cannot be checked here at all.`,
          suggestion: 'Check the spelling against the JOSE registry, or check this key by hand.',
        })
      }
    }
  }

  if (offered !== null) {
    result.algorithms.offered = offered.slice().sort(byCodeUnit)
    for (let index = 0; index < offered.length; index += 1) {
      budget.check()
      const name = offered[index]
      if (name === NONE_ALGORITHM) {
        sink.add({
          file: files.metadata,
          pointer: `/id_token_signing_alg_values_supported/${index}`,
          ruleId: 'alg-none-offered',
          message: 'The provider offers "none" as an ID token signing algorithm. A relying party that follows the metadata may negotiate an unsigned ID token, which any party on the path can then write.',
          suggestion: 'Turn "none" off at the provider, or treat this deployment as unable to authenticate anyone.',
        })
        continue
      }
      if (permitted !== null && !permitted.includes(name)) {
        // Anchored at the list rather than at the index: this is a statement
        // about the provider's offered set overlapping the policy's permitted
        // set, which is a relation between two documents rather than a property
        // of one entry.
        sink.add({
          file: files.metadata,
          pointer: '/id_token_signing_alg_values_supported',
          ruleId: 'alg-offered-not-permitted',
          message: `The provider offers "${excerpt(name, 40)}" and the policy does not permit it. That is not a failure on its own -- the client selects one algorithm and this check is about that one -- but it is surface the policy did not ask for.`,
        })
      }
    }
  }

  const selected = client.idTokenSignedResponseAlg
  if (selected !== null) {
    result.settings += 1
    result.algorithms.selected = selected
    const classified = classifyAlgorithm(selected)

    if (classified.kind === 'none') {
      sink.add({
        file: files.client,
        pointer: '/idTokenSignedResponseAlg',
        ruleId: 'alg-none-selected',
        message: 'The client selects "none" for ID token signatures, which means it accepts an unsigned ID token. Anyone who can reach the redirect URI can then assert any identity.',
        suggestion: 'Select a signing algorithm the policy permits.',
      })
    } else if (classified.kind === 'unrecognised') {
      result.unknown = true
      sink.add({
        file: files.client,
        pointer: '/idTokenSignedResponseAlg',
        ruleId: 'alg-unrecognised',
        message: `The client selects "${excerpt(selected, 40)}", which this build does not implement. It was not checked against the policy and no key was checked against it: an algorithm this tool does not carry is unsupported, which is not the same as approved.`,
        suggestion: 'Check the spelling against the JOSE registry, or check this setting by hand.',
      })
    } else {
      result.selected = classified
      if (permitted !== null && !permitted.includes(selected)) {
        sink.add({
          file: files.client,
          pointer: '/idTokenSignedResponseAlg',
          ruleId: 'alg-not-permitted',
          message: `The client selects "${excerpt(selected, 40)}" and the policy does not permit it.`,
          evidence: `permitted: ${result.algorithms.permitted.join(', ')}`,
          suggestion: 'Select a permitted algorithm, or change the policy deliberately.',
        })
      }
      if (offered !== null && !offered.includes(selected)) {
        sink.add({
          file: files.client,
          pointer: '/idTokenSignedResponseAlg',
          ruleId: 'alg-not-offered',
          message: `The client selects "${excerpt(selected, 40)}" and the provider does not offer it. Nothing this provider issues can be verified with the algorithm this client is configured to require.`,
          suggestion: 'Select an algorithm the provider offers, or use a provider that offers this one.',
        })
      }
      if (classified.symmetric) {
        sink.add({
          file: files.client,
          pointer: '/idTokenSignedResponseAlg',
          ruleId: 'alg-symmetric-selected',
          message: `"${excerpt(selected, 40)}" is a symmetric algorithm: the ID token is verified with the client secret, not with a key from the key set. This tool never reads a secret, so it checked the key set for nothing on this client's behalf and can say nothing about whether that secret is strong.`,
          suggestion: 'Use an asymmetric algorithm unless the shared secret is deliberate.',
        })
      }
    }
  }

  if (client.responseTypes !== null) {
    for (const responseType of client.responseTypes) {
      budget.check()
      result.settings += 1
      if (metadata.lists.responseTypes !== null && !metadata.lists.responseTypes.includes(responseType)) {
        sink.add({
          file: files.client,
          pointer: '/responseTypes',
          ruleId: 'response-type-not-offered',
          message: `The client requests response type "${excerpt(responseType, 60)}" and the provider does not list it. Values are compared as exact strings, spacing and order included, because that is how a provider matches them.`,
          suggestion: 'Use a spelling from "response_types_supported" verbatim.',
        })
      }
      if (policy.allowedResponseTypes !== null && !policy.allowedResponseTypes.includes(responseType)) {
        sink.add({
          file: files.client,
          pointer: '/responseTypes',
          ruleId: 'response-type-not-permitted',
          message: `The client requests response type "${excerpt(responseType, 60)}" and the policy does not permit it.`,
          suggestion: 'Remove the response type, or permit it deliberately.',
        })
      }
    }
  }

  const method = client.tokenEndpointAuthMethod
  if (method !== null) {
    /**
     * `token_endpoint_auth_methods_supported` is OPTIONAL in OpenID Connect
     * Discovery, which made it the one list this function compares against that
     * can legitimately be absent -- and an absent list used to skip the
     * comparison silently, leaving the setting counted as checked and the run
     * free to report `pass`. That is the tool's own load-bearing claim broken:
     * the client's authentication method had not been checked against the
     * provider at all.
     *
     * The specification supplies a default of `client_secret_basic` for the
     * absent member, and reading it that way would let this report
     * `auth-method-not-offered` instead. It does not, because that would be a
     * claim about the provider drawn from a document that says nothing about
     * it: providers omit the member while supporting more than the default, and
     * a false "not offered" is as wrong as a false pass. The setting is left
     * out of the checked count, the run is marked incomplete, and the reader is
     * told which document would settle it -- the same handling the PKCE check
     * below gives the same situation.
     */
    if (metadata.lists.authMethods === null) {
      result.unknown = true
      sink.add({
        file: files.metadata,
        pointer: '/token_endpoint_auth_methods_supported',
        ruleId: 'auth-method-support-unknown',
        message: `The client authenticates with "${excerpt(method, 40)}" and the discovery document does not publish "token_endpoint_auth_methods_supported", so this run did not check that method against the provider at all. The member is absent, and absence is not evidence of support; the specification's default of "client_secret_basic" is not read as one either, because a provider that omits the member may well accept more.`,
        suggestion: 'Publish "token_endpoint_auth_methods_supported" at the provider, or confirm the accepted methods by hand.',
      })
    } else {
      result.settings += 1
      if (!metadata.lists.authMethods.includes(method)) {
        sink.add({
          file: files.client,
          pointer: '/tokenEndpointAuthMethod',
          ruleId: 'auth-method-not-offered',
          message: `The client authenticates with "${excerpt(method, 40)}" and the provider does not list it in "token_endpoint_auth_methods_supported".`,
        })
      }
    }
    if (policy.allowedTokenEndpointAuthMethods !== null && !policy.allowedTokenEndpointAuthMethods.includes(method)) {
      sink.add({
        file: files.client,
        pointer: '/tokenEndpointAuthMethod',
        ruleId: 'auth-method-not-permitted',
        message: `The client authenticates with "${excerpt(method, 40)}" and the policy does not permit it.`,
      })
    }
  }

  if (policy.requirePkceS256 === true) {
    result.settings += 1
    const methods = metadata.lists.codeChallengeMethods
    if (methods === null || !methods.includes(REQUIRED_PKCE_METHOD)) {
      sink.add({
        file: files.metadata,
        pointer: '/code_challenge_methods_supported',
        ruleId: 'pkce-s256-not-offered',
        message: `The policy requires PKCE with ${REQUIRED_PKCE_METHOD} and the discovery document does not offer it${methods === null ? ' (the member is absent, and absence is not evidence of support)' : ''}.`,
        suggestion: 'Turn S256 on at the provider, or record deliberately that this deployment runs without PKCE.',
      })
    }
    if (client.pkceMethod !== REQUIRED_PKCE_METHOD) {
      sink.add({
        file: files.client,
        pointer: '/pkceMethod',
        ruleId: 'pkce-not-s256',
        message: `The policy requires PKCE with ${REQUIRED_PKCE_METHOD}; the client declares ${client.pkceMethod === null ? 'no code challenge method' : `"${excerpt(client.pkceMethod, 40)}"`}. "plain" offers no protection against an intercepted authorization code.`,
        suggestion: `Set "pkceMethod" to "${REQUIRED_PKCE_METHOD}".`,
      })
    }
  }

  return result
}

/** Inspect one key, and decide what the rotation and algorithm policy makes of it. */
function checkKey(sink, file, entry, policy, unknownSink) {
  const { raw, pointer } = entry
  const row = { kid: null, kty: null, alg: null, status: 'refused', index: entry.index }
  let refused = false

  // Walked in document order rather than sorted: each of these findings lands
  // at its own pointer, so the report's own sort decides what a reader sees and
  // an ordering here would be a second, unobservable one.
  for (const member of Object.keys(raw)) {
    if (KNOWN_KEY_MEMBERS.includes(member) || PRIVATE_PARAMETERS.includes(member)) continue
    sink.add({
      file,
      pointer: `${pointer}/${member}`,
      ruleId: 'jwk-member-unknown',
      message: `This key declares "${excerpt(member, 60)}", which this build does not recognise. JWK members are extensible, so it was reported and the rest of the key was still read; nothing about it was checked.`,
    })
  }

  const privateParameters = privateParametersIn(raw)
  if (privateParameters.length > 0) {
    refused = true
    sink.add({
      file,
      pointer,
      ruleId: 'jwk-private-material',
      message: `This key carries ${privateParameters.map((name) => `"${name}"`).join(', ')}, which hold private or symmetric key material. A key set is published; anything in it is public. The values were not read, not measured and not reported.`,
      suggestion: 'Export the public half of the key set and rotate every key that was published with its private half.',
    })
  }

  if (raw.kid === undefined) {
    refused = true
    sink.add({
      file,
      pointer,
      ruleId: 'jwk-kid-missing',
      message: 'This key declares no "kid". Without one a relying party cannot tell which key signed a token, so a rotation cannot be staged: the old and the new key are indistinguishable and every verifier must try them all.',
      suggestion: 'Give every key a stable, unique "kid" before publishing it.',
    })
  } else if (!isIdentifier(raw.kid)) {
    refused = true
    sink.add({
      file,
      pointer: `${pointer}/kid`,
      ruleId: 'jwk-kid-invalid',
      message: `This key has no usable "kid"; it is ${describeValue(raw.kid)}. A key id is 1-120 characters from [A-Za-z0-9._:/+=~-], starting with a letter or digit.`,
    })
  } else row.kid = raw.kid

  if (!isToken(raw.kty)) {
    sink.add({
      file,
      pointer: `${pointer}/kty`,
      ruleId: 'jwk-invalid',
      message: `"kty" must be a key type name such as RSA; it is ${describeValue(raw.kty)}.`,
    })
    return { row, unknown: false }
  }
  row.kty = raw.kty

  if (!KEY_TYPES.includes(raw.kty)) {
    sink.add({
      file,
      pointer: `${pointer}/kty`,
      ruleId: 'jwk-kty-unsupported',
      message: `This key declares kty "${excerpt(raw.kty, 40)}", which this build does not inspect. It was not checked against the policy and it was not counted as a usable key: a key type this tool cannot read is unsupported, which is not the same as approved.`,
      suggestion: 'Check this key by hand, or remove it from the published key set.',
    })
    row.status = 'unknown'
    unknownSink.unknown = true
    return { row, unknown: true }
  }

  if (raw.kty === 'oct') {
    // Reached whether or not `k` is present: a symmetric key has no public
    // half, so its appearance in a published key set is the finding.
    if (privateParameters.length === 0) {
      sink.add({
        file,
        pointer: `${pointer}/kty`,
        ruleId: 'jwk-private-material',
        message: 'This is a symmetric key. A symmetric key has no public half, so publishing one in a key set publishes the secret itself, whether or not "k" is present in this copy.',
        suggestion: 'Remove the key from the published set and rotate the secret.',
      })
    }
    return { row, unknown: false }
  }

  if (raw.use !== undefined) {
    if (!isToken(raw.use) || !KEY_USES.includes(raw.use)) {
      refused = true
      sink.add({
        file,
        pointer: `${pointer}/use`,
        ruleId: 'jwk-invalid',
        message: `"use" must be one of ${KEY_USES.join(', ')}; it is ${describeValue(raw.use)}.`,
      })
    } else if (raw.use === 'enc') {
      row.status = 'encryption'
      return { row, unknown: false }
    }
  }

  if (raw.alg === undefined) {
    sink.add({
      file,
      pointer,
      ruleId: 'jwk-alg-undeclared',
      message: 'This key declares no "alg", so there is nothing to check against the policy. An undeclared algorithm is unknown, not permitted: a verifier is free to use this key with any algorithm its key type allows, and this tool will not guess which.',
      suggestion: 'Declare "alg" on every key in the published set.',
    })
    row.status = 'unknown'
    unknownSink.unknown = true
    return { row, unknown: true }
  }

  if (!isToken(raw.alg)) {
    sink.add({
      file,
      pointer: `${pointer}/alg`,
      ruleId: 'jwk-invalid',
      message: `"alg" must be an algorithm name such as RS256; it is ${describeValue(raw.alg)}.`,
    })
    return { row, unknown: false }
  }
  row.alg = raw.alg

  const classified = classifyAlgorithm(raw.alg)
  if (classified.kind === 'none') {
    sink.add({
      file,
      pointer: `${pointer}/alg`,
      ruleId: 'jwk-alg-none',
      message: 'This key declares alg "none". A key that signs nothing is not a signing key, and its presence in the set invites a verifier to accept an unsigned token as if this key had produced it.',
      suggestion: 'Remove the entry.',
    })
    return { row, unknown: false }
  }
  if (classified.kind === 'unrecognised') {
    sink.add({
      file,
      pointer: `${pointer}/alg`,
      ruleId: 'jwk-alg-unrecognised',
      message: `This key declares alg "${excerpt(raw.alg, 40)}", which this build does not implement. It was not checked against the policy and it was not counted as a usable key: an algorithm this tool does not carry is unsupported, which is not the same as approved.`,
      suggestion: 'Check the spelling against the JOSE registry, or check this key by hand.',
    })
    row.status = 'unknown'
    unknownSink.unknown = true
    return { row, unknown: true }
  }

  if (classified.kty !== raw.kty) {
    refused = true
    sink.add({
      file,
      pointer: `${pointer}/alg`,
      ruleId: 'jwk-alg-key-mismatch',
      message: `Algorithm "${excerpt(raw.alg, 40)}" needs a ${classified.kty} key and this key declares kty "${excerpt(raw.kty, 40)}". Nothing can be verified with this pairing.`,
    })
  } else if (classified.curves !== null) {
    if (!isToken(raw.crv)) {
      refused = true
      sink.add({
        file,
        pointer: `${pointer}/crv`,
        ruleId: 'jwk-invalid',
        message: `"crv" must be a curve name such as P-256; it is ${describeValue(raw.crv)}.`,
      })
    } else if (!classified.curves.includes(raw.crv)) {
      refused = true
      sink.add({
        file,
        pointer: `${pointer}/crv`,
        ruleId: 'jwk-curve-mismatch',
        message: `Algorithm "${excerpt(raw.alg, 40)}" is defined over ${classified.curves.join(' or ')} and this key declares "${excerpt(raw.crv, 40)}". A curve changed without its algorithm label is a key nothing can verify with.`,
      })
    }
  }

  const material = inspectKeyMaterial(raw, raw.kty)
  for (const problem of material.problems) {
    refused = true
    sink.add({
      file,
      pointer: `${pointer}/${problem.parameter}`,
      ruleId: 'jwk-invalid',
      message: `Key parameter "${problem.parameter}" ${problem.reason === 'missing' ? 'is absent' : problem.reason === 'not-a-string' ? 'is not a string' : problem.reason === 'too-long' ? 'is longer than this build reads' : problem.reason === 'not-base64url' ? 'is not base64url, so it was not decoded' : 'could not be measured'}.`,
    })
  }

  if (raw.kty === 'RSA' && material.modulusBits !== null && policy.minRsaModulusBits !== null) {
    if (material.modulusBits < policy.minRsaModulusBits) {
      refused = true
      sink.add({
        file,
        pointer: `${pointer}/n`,
        ruleId: 'jwk-rsa-modulus-short',
        message: `This RSA key has a ${material.modulusBits}-bit modulus and the policy requires at least ${policy.minRsaModulusBits}. The length was measured from the encoded modulus with its leading zero bytes removed, so a short key padded to look long is still reported short.`,
        suggestion: 'Rotate to a key of at least the policy size.',
      })
    }
  }

  if (material.coordinateBytes !== null && isToken(raw.crv)) {
    const expected = coordinateBytesFor(raw.crv)
    if (expected !== null && material.coordinateBytes !== expected) {
      refused = true
      sink.add({
        file,
        pointer: `${pointer}/x`,
        ruleId: 'jwk-invalid',
        message: `Key parameter "x" decodes to ${material.coordinateBytes} bytes and curve "${excerpt(raw.crv, 40)}" uses ${expected}. The key and its curve label do not describe the same key.`,
      })
    }
  }

  if (refused) return { row, unknown: false }

  if (policy.allowedIdTokenSigningAlgs !== null && !policy.allowedIdTokenSigningAlgs.includes(raw.alg)) {
    row.status = 'not-permitted'
    sink.add({
      file,
      pointer: `${pointer}/alg`,
      ruleId: 'jwk-alg-not-permitted',
      message: `This key declares alg "${excerpt(raw.alg, 40)}" and the policy does not permit it, so it was not counted as a key this deployment may rotate to.`,
      suggestion: 'Remove the key, or permit the algorithm deliberately.',
    })
    return { row, unknown: false }
  }

  row.status = 'usable'
  return { row, unknown: false }
}

/** The key set as a whole: every key, then rotation readiness. */
function checkKeys(sink, files, jwks, policy, selected, budget) {
  const rows = []
  const seenKids = new Map()
  const unknownSink = { unknown: false }

  for (const entry of jwks.entries) {
    budget.check()
    const { row } = checkKey(sink, files.jwks, entry, policy, unknownSink)

    if (row.kid !== null) {
      const first = seenKids.get(row.kid)
      if (first !== undefined) {
        row.status = 'refused'
        sink.add({
          file: files.jwks,
          pointer: `${entry.pointer}/kid`,
          ruleId: 'jwk-kid-duplicate',
          message: `Key id "${excerpt(row.kid, 60)}" is declared at ${first} and here. A rotation selects a key by its id, and two keys answering to one id make that selection undefined.`,
          suggestion: 'Give each key a distinct id.',
        })
      } else seenKids.set(row.kid, `${entry.pointer}/kid`)
    }
    rows.push(row)
  }

  // Re-read after the loop rather than inside it. A budget that can be
  // exhausted mid-loop must be re-checked once the loop is over, or a run that
  // stopped early reaches the conclusions below with a key list that is a floor
  // rather than an answer -- and "no usable key" would then be asserted about
  // keys nobody looked at.
  budget.check()

  const usable = rows.filter((row) => row.status === 'usable')
  const evaluated = rows.length

  if (usable.length === 0) {
    sink.add({
      file: files.jwks,
      pointer: '/keys',
      ruleId: 'jwks-no-signing-key',
      message: `The key set holds ${evaluated} key(s) and none of them is a signing key this policy permits and this build can check. Nothing here can verify an ID token.`,
      suggestion: 'Publish at least one signing key whose algorithm the policy permits.',
    })
  } else if (policy.minimumKeys !== null && usable.length < policy.minimumKeys) {
    sink.add({
      file: files.jwks,
      pointer: '/keys',
      ruleId: 'jwks-too-few-keys',
      message: `The key set holds ${usable.length} usable signing key(s) and the policy requires ${policy.minimumKeys}. A rotation needs the next key published and trusted before the current one stops signing; with fewer, every rotation is an outage or a gap.`,
      suggestion: 'Publish the incoming key alongside the outgoing one.',
    })
  }

  if (selected !== null && !selected.symmetric) {
    if (!usable.some((row) => row.alg === selected.name)) {
      sink.add({
        file: files.jwks,
        pointer: '/keys',
        ruleId: 'jwks-selected-alg-unusable',
        message: `The client accepts ID tokens signed with "${excerpt(selected.name, 40)}" and the key set holds no usable key declaring that algorithm. Every token this provider issues to this client would fail verification.`,
        suggestion: 'Publish a key for the algorithm the client selected, or select an algorithm the key set carries.',
      })
    }
  }

  return {
    rows: rows
      .slice()
      .sort((left, right) => byCodeUnit(left.kid === null ? '' : left.kid, right.kid === null ? '' : right.kid) || left.index - right.index)
      .map((row) => ({ kid: row.kid, kty: row.kty, alg: row.alg, status: row.status })),
    evaluated,
    usable: usable.length,
    unknown: unknownSink.unknown,
  }
}

/**
 * Run every check, in phases.
 *
 * Each phase writes into the profile only once it has finished. If the time
 * budget fires part way through a phase, the exception leaves that phase's
 * section of the profile at its initial empty value rather than at a partial
 * one, and the caller marks the run incomplete: a half-filled key list read as
 * a whole one is exactly the shape of a false conclusion.
 */
export function runChecks(sink, files, compiled, budget) {
  const profile = {
    issuer: null,
    expectedIssuer: null,
    issuerMatches: null,
    redirectUris: [],
    postLogoutUris: [],
    signingKeys: [],
    algorithms: { selected: null, offered: [], permitted: [] },
  }
  const counts = { endpoints: 0, redirectUris: 0, postLogoutUris: 0, keys: 0, usableKeys: 0, settings: 0 }
  const state = { profile, counts, incomplete: false }

  const { metadata, client, policy, jwks } = compiled

  const issuer = checkIssuer(sink, files, metadata, client)
  profile.issuer = issuer.issuer
  profile.expectedIssuer = issuer.expectedIssuer
  profile.issuerMatches = issuer.matches
  counts.settings += issuer.settings
  if (issuer.incomplete) state.incomplete = true

  counts.endpoints = checkEndpoints(sink, files, metadata, issuer.origin, budget)

  const redirects = checkRedirects(sink, files, client, policy, budget)
  profile.redirectUris = redirects.redirectUris
  profile.postLogoutUris = redirects.postLogoutUris
  counts.redirectUris = redirects.counts.redirectUris
  counts.postLogoutUris = redirects.counts.postLogoutUris
  if (redirects.refused > 0) state.incomplete = true

  const settings = checkSettings(sink, files, metadata, client, policy, budget)
  profile.algorithms = settings.algorithms
  counts.settings += settings.settings
  if (settings.unknown) state.incomplete = true

  const keys = checkKeys(sink, files, jwks, policy, settings.selected, budget)
  profile.signingKeys = keys.rows
  counts.keys = keys.evaluated
  counts.usableKeys = keys.usable
  if (keys.unknown) state.incomplete = true

  return state
}
