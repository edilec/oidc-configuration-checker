/**
 * The four input documents, compiled from parsed JSON into the shapes the
 * checks work on.
 *
 * Two of the four are exports: `metadata.json` is the discovery document an
 * OpenID Provider publishes, and `jwks.json` is the key set it publishes. This
 * tool reads copies that somebody already saved, and it never goes and gets
 * them. The other two -- `client.json` and `policy.json` -- are documents this
 * tool defines, and they carry a `schemaVersion`.
 *
 * That split decides how an unknown key is treated, and the difference is
 * deliberate:
 *
 * - In a document **this tool defines**, an unknown key is refused and the
 *   document is not used. A one-character typo must not silently disable a
 *   check, and a field named `clientSecret` must not be read into this tool by
 *   accident.
 * - In the **discovery document**, an unknown key is reported and the document
 *   is still read. OpenID Connect Discovery says a provider may publish
 *   additional metadata, and half the providers in the world do. Refusing them
 *   would be a checker that rejects every real input -- a false refusal is a
 *   defect exactly as much as a false pass.
 *
 * The JWKS sits with the first group for its top-level members and with the
 * second for the members of a key, for the same reason in both directions.
 */

import {
  MAX_DESCRIPTION_LENGTH,
  byCodeUnit,
  describeValue,
  excerpt,
  isIdentifier,
  isPlainObject,
  isResponseType,
  isToken,
} from './text.mjs'

/** The only version this build reads for the two documents this tool defines. */
export const DOCUMENT_SCHEMA_VERSION = '1'

export const CLIENT_KEYS = Object.freeze([
  'clientId', 'description', 'expectedIssuer', 'idTokenSignedResponseAlg', 'pkceMethod',
  'postLogoutRedirectUris', 'redirectUris', 'responseTypes', 'schemaVersion', 'tokenEndpointAuthMethod',
])

export const CLIENT_REQUIRED = Object.freeze([
  'clientId', 'expectedIssuer', 'idTokenSignedResponseAlg', 'redirectUris', 'responseTypes',
  'schemaVersion', 'tokenEndpointAuthMethod',
])

export const POLICY_KEYS = Object.freeze([
  'allowedIdTokenSigningAlgs', 'allowedPostLogoutRedirectUris', 'allowedRedirectUris',
  'allowedResponseTypes', 'allowedTokenEndpointAuthMethods', 'description', 'minRsaModulusBits',
  'minimumKeys', 'redirectUriMatching', 'requirePkceS256', 'schemaVersion',
])

export const POLICY_REQUIRED = Object.freeze([
  'allowedIdTokenSigningAlgs', 'allowedPostLogoutRedirectUris', 'allowedRedirectUris',
  'allowedResponseTypes', 'allowedTokenEndpointAuthMethods', 'minRsaModulusBits', 'minimumKeys',
  'redirectUriMatching', 'requirePkceS256', 'schemaVersion',
])

/**
 * Discovery metadata members this build recognises, from OpenID Connect
 * Discovery 1.0 and RFC 8414 plus the extensions providers publish in practice.
 * A member outside this list is reported as unknown and the document is still
 * read.
 */
export const KNOWN_METADATA_KEYS = Object.freeze([
  'acr_values_supported', 'authorization_endpoint', 'authorization_response_iss_parameter_supported',
  'backchannel_logout_session_supported', 'backchannel_logout_supported', 'check_session_iframe',
  'claim_types_supported', 'claims_locales_supported', 'claims_parameter_supported', 'claims_supported',
  'code_challenge_methods_supported', 'device_authorization_endpoint', 'display_values_supported',
  'dpop_signing_alg_values_supported', 'end_session_endpoint', 'frontchannel_logout_session_supported',
  'frontchannel_logout_supported', 'grant_types_supported', 'id_token_encryption_alg_values_supported',
  'id_token_encryption_enc_values_supported', 'id_token_signing_alg_values_supported',
  'introspection_endpoint', 'introspection_endpoint_auth_methods_supported',
  'introspection_endpoint_auth_signing_alg_values_supported', 'issuer', 'jwks_uri',
  'mtls_endpoint_aliases', 'op_policy_uri', 'op_tos_uri',
  'pushed_authorization_request_endpoint', 'registration_endpoint',
  'request_object_encryption_alg_values_supported', 'request_object_encryption_enc_values_supported',
  'request_object_signing_alg_values_supported', 'request_parameter_supported',
  'request_uri_parameter_supported', 'require_pushed_authorization_requests',
  'require_request_uri_registration', 'response_modes_supported', 'response_types_supported',
  'revocation_endpoint', 'revocation_endpoint_auth_methods_supported',
  'revocation_endpoint_auth_signing_alg_values_supported', 'scopes_supported', 'service_documentation',
  'subject_types_supported', 'tls_client_certificate_bound_access_tokens', 'token_endpoint',
  'token_endpoint_auth_methods_supported', 'token_endpoint_auth_signing_alg_values_supported',
  'ui_locales_supported', 'userinfo_encryption_alg_values_supported',
  'userinfo_encryption_enc_values_supported', 'userinfo_endpoint', 'userinfo_signing_alg_values_supported',
])

/**
 * Members without which a relying party cannot complete an authorization code
 * flow or verify an ID token. Their absence is a verdict about the document,
 * not a gap in this tool's evidence.
 */
export const REQUIRED_METADATA_KEYS = Object.freeze([
  'authorization_endpoint', 'id_token_signing_alg_values_supported', 'issuer', 'jwks_uri',
  'response_types_supported', 'subject_types_supported', 'token_endpoint',
])

/** Members that carry a URL the provider serves, checked for transport and origin. */
export const METADATA_ENDPOINT_KEYS = Object.freeze([
  'authorization_endpoint', 'check_session_iframe', 'device_authorization_endpoint',
  'end_session_endpoint', 'introspection_endpoint', 'jwks_uri',
  'pushed_authorization_request_endpoint', 'registration_endpoint', 'revocation_endpoint',
  'token_endpoint', 'userinfo_endpoint',
])

/** The only top-level member a JWKS may carry here. */
export const JWKS_KEYS = Object.freeze(['keys'])

function unknownKeys(value, allowed) {
  return Object.keys(value).filter((key) => !allowed.includes(key)).sort(byCodeUnit)
}

function namedKeys(keys) {
  return keys.map((key) => `"${excerpt(key, 60)}"`).join(', ')
}

/**
 * Check the envelope of a document this tool defines: a plain object, an
 * exhaustive key set, and the one schema version this build implements.
 * Returns `false` when the document is unusable and a finding has been emitted.
 */
function checkEnvelope(sink, file, value, allowedKeys, ruleId, noun) {
  if (!isPlainObject(value)) {
    sink.add({
      file,
      ruleId,
      message: `${file} must hold a JSON object describing the ${noun}; it holds ${describeValue(value)}.`,
    })
    return false
  }
  const stray = unknownKeys(value, allowedKeys)
  if (stray.length > 0) {
    sink.add({
      file,
      ruleId,
      message: `${file} declares unknown key(s) ${namedKeys(stray)}; known keys are ${allowedKeys.join(', ')}. An unknown key is refused rather than ignored, so a typo cannot disable a check and no credential field can be read into this tool by accident.`,
      suggestion: 'Remove the unknown key, or correct its spelling.',
    })
    return false
  }
  if (value.schemaVersion !== DOCUMENT_SCHEMA_VERSION) {
    sink.add({
      file,
      pointer: '/schemaVersion',
      ruleId: 'schema-version-unsupported',
      message: `${file} declares schemaVersion ${describeValue(value.schemaVersion)}; this build implements version "${DOCUMENT_SCHEMA_VERSION}" only, and it does not guess at another one.`,
      suggestion: `Re-export the document as schemaVersion "${DOCUMENT_SCHEMA_VERSION}".`,
    })
    return false
  }
  return true
}

/**
 * Compile a list of short registry values -- algorithm names, response types,
 * authentication methods.
 *
 * An entry that is not a usable value is refused and counted rather than
 * dropped: a list read in part would let a client look as if it declared fewer
 * response types than it does, and the report would then describe a
 * configuration nobody deployed.
 */
function compileTokenList(sink, file, pointer, raw, options) {
  const { ruleId, limit, limitRule, limitName, noun, shape } = options

  if (!Array.isArray(raw)) {
    sink.add({ file, pointer, ruleId, message: `"${options.field}" must be an array of ${noun}; it is ${describeValue(raw)}.` })
    return null
  }
  if (raw.length > limit) {
    sink.add({
      file,
      pointer,
      ruleId: limitRule,
      message: `"${options.field}" holds ${raw.length} entries, above the ${limitName} limit of ${limit}; the list was refused rather than read in part.`,
      suggestion: `Raise --${limitName.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)}, or shorten the list.`,
    })
    return null
  }

  const values = []
  let refused = 0
  for (let index = 0; index < raw.length; index += 1) {
    const candidate = raw[index]
    if (!shape(candidate)) {
      refused += 1
      sink.add({
        file,
        pointer: `${pointer}/${index}`,
        ruleId,
        message: `This entry is not a usable ${noun.replace(/s$/, '')}; it is ${describeValue(candidate)}.`,
      })
      continue
    }
    values.push(candidate)
  }
  return { values, refused }
}

/**
 * Compile the discovery document.
 *
 * Returns `null` only when the document as a whole is unusable. A single
 * malformed member produces a finding and leaves the rest readable: refusing a
 * whole discovery document because one vendor extension is an array would tell
 * a reader nothing about the issuer, which is the member they came for.
 */
export function compileMetadata(sink, file, value, limits) {
  if (!isPlainObject(value)) {
    sink.add({
      file,
      ruleId: 'metadata-invalid',
      message: `${file} must hold the JSON object a provider publishes at its discovery endpoint; it holds ${describeValue(value)}.`,
    })
    return null
  }

  const keys = Object.keys(value)
  if (keys.length > limits.maxMetadataKeys) {
    sink.add({
      file,
      ruleId: 'too-many-metadata-keys',
      message: `${file} declares ${keys.length} members, above the maxMetadataKeys limit of ${limits.maxMetadataKeys}; nothing was read from it rather than a prefix being read and reported as the whole.`,
      suggestion: 'Raise --max-metadata-keys, or check that this is a discovery document.',
    })
    return null
  }

  // Walked in document order rather than sorted: each unknown member gets its
  // own finding at its own pointer, so the report's own sort decides the order
  // a reader sees and an ordering here would be a second, unobservable one.
  for (const key of keys) {
    if (KNOWN_METADATA_KEYS.includes(key)) continue
    sink.add({
      file,
      pointer: `/${key}`,
      ruleId: 'metadata-key-unknown',
      message: `${file} declares "${excerpt(key, 60)}", which this build does not recognise. Discovery metadata is extensible, so the member was reported and the rest of the document was still read; nothing about it was checked.`,
    })
  }

  let refused = 0
  for (const key of REQUIRED_METADATA_KEYS) {
    if (value[key] === undefined) {
      sink.add({
        file,
        ruleId: 'metadata-field-missing',
        message: `${file} declares no "${key}". A relying party cannot complete an authorization code flow or verify an ID token without it.`,
        suggestion: `Re-export the discovery document from the provider, or add "${key}".`,
      })
    }
  }

  let issuer = null
  if (value.issuer !== undefined) {
    if (typeof value.issuer === 'string') issuer = value.issuer
    else {
      refused += 1
      sink.add({
        file,
        pointer: '/issuer',
        ruleId: 'metadata-invalid',
        message: `"issuer" must be a string; it is ${describeValue(value.issuer)}.`,
      })
    }
  }

  const endpoints = []
  for (const key of METADATA_ENDPOINT_KEYS) {
    const endpoint = value[key]
    if (endpoint === undefined) continue
    if (typeof endpoint !== 'string') {
      refused += 1
      sink.add({
        file,
        pointer: `/${key}`,
        ruleId: 'metadata-invalid',
        message: `"${key}" must be a string holding a URL; it is ${describeValue(endpoint)}.`,
      })
      continue
    }
    endpoints.push({ field: key, value: endpoint })
  }

  /**
   * The discovery lists this build reads.
   *
   * Four of the five have a reader in `src/checks.mjs`;
   * `subject_types_supported` does not, and that is deliberate rather than an
   * oversight. It is compiled because compiling it is what *refuses* it: a
   * member of the wrong shape, an entry that is not a token, or a list above
   * `maxListEntries` each raise a finding here, and a required member this
   * build could not read must not pass unremarked. What it has no reader for is
   * a comparison -- the client document this tool defines declares no subject
   * type, so there is nothing to compare it against, and inventing a rule about
   * which subject types a provider ought to offer would be this tool deciding a
   * deployment question it was not asked. The compiled values sit in `lists`
   * because the loop is uniform; `lists.subjectTypes` having no reader is the
   * honest state, not a missing check.
   */
  const lists = {}
  const LIST_SPECS = [
    { field: 'id_token_signing_alg_values_supported', name: 'idTokenAlgs', shape: isToken, noun: 'algorithm names', limit: limits.maxAlgorithms, limitRule: 'too-many-algorithms', limitName: 'maxAlgorithms' },
    { field: 'response_types_supported', name: 'responseTypes', shape: isResponseType, noun: 'response types', limit: limits.maxListEntries, limitRule: 'too-many-list-entries', limitName: 'maxListEntries' },
    { field: 'subject_types_supported', name: 'subjectTypes', shape: isToken, noun: 'subject types', limit: limits.maxListEntries, limitRule: 'too-many-list-entries', limitName: 'maxListEntries' },
    { field: 'token_endpoint_auth_methods_supported', name: 'authMethods', shape: isToken, noun: 'authentication methods', limit: limits.maxListEntries, limitRule: 'too-many-list-entries', limitName: 'maxListEntries' },
    { field: 'code_challenge_methods_supported', name: 'codeChallengeMethods', shape: isToken, noun: 'code challenge methods', limit: limits.maxListEntries, limitRule: 'too-many-list-entries', limitName: 'maxListEntries' },
  ]

  for (const spec of LIST_SPECS) {
    if (value[spec.field] === undefined) {
      lists[spec.name] = null
      continue
    }
    const compiled = compileTokenList(sink, file, `/${spec.field}`, value[spec.field], {
      ...spec, ruleId: 'metadata-invalid',
    })
    if (compiled === null) {
      lists[spec.name] = null
      refused += 1
      continue
    }
    refused += compiled.refused
    lists[spec.name] = compiled.values
  }

  return { issuer, endpoints, lists, refused }
}

/** Compile the client settings document. */
export function compileClient(sink, file, value, limits) {
  if (!checkEnvelope(sink, file, value, CLIENT_KEYS, 'client-invalid', 'relying party')) return null

  for (const key of CLIENT_REQUIRED) {
    if (value[key] === undefined) {
      sink.add({
        file,
        ruleId: 'client-field-missing',
        message: `${file} declares no "${key}", so the check that needs it was not performed.`,
        suggestion: `Add "${key}" to the client document.`,
      })
    }
  }

  let refused = 0
  const client = {
    clientId: null,
    expectedIssuer: null,
    idTokenSignedResponseAlg: null,
    tokenEndpointAuthMethod: null,
    pkceMethod: null,
    responseTypes: null,
    redirectUris: null,
    postLogoutRedirectUris: null,
  }

  const scalar = (field, shape, noun) => {
    const raw = value[field]
    if (raw === undefined) return
    if (!shape(raw)) {
      refused += 1
      sink.add({
        file,
        pointer: `/${field}`,
        ruleId: 'client-invalid',
        message: `"${field}" must be ${noun}; it is ${describeValue(raw)}.`,
      })
      return
    }
    client[field] = raw
  }

  scalar('clientId', isIdentifier, 'an identifier of 1-120 characters from [A-Za-z0-9._:/+=~-]')
  scalar('expectedIssuer', (raw) => typeof raw === 'string' && raw.length > 0, 'a string holding the issuer URL this client expects')
  scalar('idTokenSignedResponseAlg', isToken, 'a JWS algorithm name such as RS256')
  scalar('tokenEndpointAuthMethod', isToken, 'an authentication method name such as private_key_jwt')
  scalar('pkceMethod', isToken, 'a code challenge method name such as S256')

  if (value.description !== undefined && (typeof value.description !== 'string' || value.description.length > MAX_DESCRIPTION_LENGTH)) {
    refused += 1
    sink.add({
      file,
      pointer: '/description',
      ruleId: 'client-invalid',
      message: `"description" must be a string of at most ${MAX_DESCRIPTION_LENGTH} characters; it is ${describeValue(value.description)}.`,
    })
  }

  if (value.responseTypes !== undefined) {
    const compiled = compileTokenList(sink, file, '/responseTypes', value.responseTypes, {
      field: 'responseTypes',
      ruleId: 'client-invalid',
      shape: isResponseType,
      noun: 'response types',
      limit: limits.maxListEntries,
      limitRule: 'too-many-list-entries',
      limitName: 'maxListEntries',
    })
    if (compiled === null) refused += 1
    else {
      refused += compiled.refused
      client.responseTypes = compiled.values
    }
  }

  for (const field of ['postLogoutRedirectUris', 'redirectUris']) {
    const raw = value[field]
    if (raw === undefined) continue
    if (!Array.isArray(raw)) {
      refused += 1
      sink.add({
        file,
        pointer: `/${field}`,
        ruleId: 'client-invalid',
        message: `"${field}" must be an array of redirect URIs; it is ${describeValue(raw)}.`,
      })
      continue
    }
    if (raw.length > limits.maxRedirectUris) {
      refused += 1
      sink.add({
        file,
        pointer: `/${field}`,
        ruleId: 'too-many-redirect-uris',
        message: `"${field}" holds ${raw.length} entries, above the maxRedirectUris limit of ${limits.maxRedirectUris}; the list was refused rather than read in part.`,
        suggestion: 'Raise --max-redirect-uris, or shorten the list.',
      })
      continue
    }
    client[field] = raw
  }

  return { ...client, refused }
}

/** Compile the policy document. */
export function compilePolicy(sink, file, value, limits) {
  if (!checkEnvelope(sink, file, value, POLICY_KEYS, 'policy-invalid', 'policy')) return null

  for (const key of POLICY_REQUIRED) {
    if (value[key] === undefined) {
      sink.add({
        file,
        ruleId: 'policy-field-missing',
        message: `${file} declares no "${key}", so the check it governs was not performed and nothing about it can be reported as satisfied.`,
        suggestion: `Add "${key}" to the policy document.`,
      })
    }
  }

  let refused = 0
  const policy = {
    redirectUriMatching: null,
    allowedRedirectUris: null,
    allowedPostLogoutRedirectUris: null,
    allowedIdTokenSigningAlgs: null,
    allowedResponseTypes: null,
    allowedTokenEndpointAuthMethods: null,
    requirePkceS256: null,
    minimumKeys: null,
    minRsaModulusBits: null,
  }

  if (value.redirectUriMatching !== undefined) {
    if (isToken(value.redirectUriMatching)) policy.redirectUriMatching = value.redirectUriMatching
    else {
      refused += 1
      sink.add({
        file,
        pointer: '/redirectUriMatching',
        ruleId: 'policy-invalid',
        message: `"redirectUriMatching" must be a name such as "exact"; it is ${describeValue(value.redirectUriMatching)}.`,
      })
    }
  }

  if (value.requirePkceS256 !== undefined) {
    if (typeof value.requirePkceS256 === 'boolean') policy.requirePkceS256 = value.requirePkceS256
    else {
      refused += 1
      sink.add({
        file,
        pointer: '/requirePkceS256',
        ruleId: 'policy-invalid',
        message: `"requirePkceS256" must be true or false; it is ${describeValue(value.requirePkceS256)}.`,
      })
    }
  }

  const integer = (field, low, high) => {
    const raw = value[field]
    if (raw === undefined) return
    if (!Number.isInteger(raw) || raw < low || raw > high) {
      refused += 1
      sink.add({
        file,
        pointer: `/${field}`,
        ruleId: 'policy-invalid',
        message: `"${field}" must be an integer between ${low} and ${high}; it is ${describeValue(raw)}.`,
      })
      return
    }
    policy[field] = raw
  }

  integer('minimumKeys', 0, 1000)
  integer('minRsaModulusBits', 512, 16384)

  if (value.description !== undefined && (typeof value.description !== 'string' || value.description.length > MAX_DESCRIPTION_LENGTH)) {
    refused += 1
    sink.add({
      file,
      pointer: '/description',
      ruleId: 'policy-invalid',
      message: `"description" must be a string of at most ${MAX_DESCRIPTION_LENGTH} characters; it is ${describeValue(value.description)}.`,
    })
  }

  const LIST_SPECS = [
    { field: 'allowedIdTokenSigningAlgs', shape: isToken, noun: 'algorithm names', limit: limits.maxAlgorithms, limitRule: 'too-many-algorithms', limitName: 'maxAlgorithms' },
    { field: 'allowedResponseTypes', shape: isResponseType, noun: 'response types', limit: limits.maxListEntries, limitRule: 'too-many-list-entries', limitName: 'maxListEntries' },
    { field: 'allowedTokenEndpointAuthMethods', shape: isToken, noun: 'authentication methods', limit: limits.maxListEntries, limitRule: 'too-many-list-entries', limitName: 'maxListEntries' },
  ]

  for (const spec of LIST_SPECS) {
    if (value[spec.field] === undefined) continue
    const compiled = compileTokenList(sink, file, `/${spec.field}`, value[spec.field], { ...spec, ruleId: 'policy-invalid' })
    if (compiled === null) {
      refused += 1
      continue
    }
    refused += compiled.refused
    policy[spec.field] = compiled.values
  }

  for (const field of ['allowedPostLogoutRedirectUris', 'allowedRedirectUris']) {
    const raw = value[field]
    if (raw === undefined) continue
    if (!Array.isArray(raw)) {
      refused += 1
      sink.add({
        file,
        pointer: `/${field}`,
        ruleId: 'policy-invalid',
        message: `"${field}" must be an array of redirect URIs; it is ${describeValue(raw)}.`,
      })
      continue
    }
    if (raw.length > limits.maxRedirectUris) {
      refused += 1
      sink.add({
        file,
        pointer: `/${field}`,
        ruleId: 'too-many-redirect-uris',
        message: `"${field}" holds ${raw.length} entries, above the maxRedirectUris limit of ${limits.maxRedirectUris}; the list was refused rather than read in part.`,
        suggestion: 'Raise --max-redirect-uris, or shorten the list.',
      })
      continue
    }
    policy[field] = raw
  }

  return { ...policy, refused }
}

/**
 * Compile the key set.
 *
 * Only the envelope and the shape of each entry are decided here. What a key
 * means -- whether its algorithm is one this build implements, whether the
 * policy permits it, whether it can verify what the client selected -- is
 * decided in `checks.mjs`, because those are questions about the policy as much
 * as about the key.
 */
export function compileJwks(sink, file, value, limits) {
  if (!isPlainObject(value)) {
    sink.add({
      file,
      ruleId: 'document-invalid',
      message: `${file} must hold a JSON object with a "keys" array, as a provider publishes it; it holds ${describeValue(value)}.`,
    })
    return null
  }
  const stray = unknownKeys(value, JWKS_KEYS)
  if (stray.length > 0) {
    sink.add({
      file,
      ruleId: 'document-invalid',
      message: `${file} declares top-level key(s) ${namedKeys(stray)}; a key set carries "keys" and nothing else here. A member outside that is refused unread, so private material parked beside the key set cannot reach this report.`,
      suggestion: 'Publish the key set as {"keys": [...]}.',
    })
    return null
  }
  if (!Array.isArray(value.keys)) {
    sink.add({
      file,
      pointer: '/keys',
      ruleId: 'document-invalid',
      message: `"keys" must be an array; it is ${describeValue(value.keys)}.`,
    })
    return null
  }
  if (value.keys.length > limits.maxKeys) {
    sink.add({
      file,
      pointer: '/keys',
      ruleId: 'too-many-keys',
      message: `${file} declares ${value.keys.length} keys, above the maxKeys limit of ${limits.maxKeys}; nothing was compiled from it rather than a prefix being read and reported as the whole.`,
      suggestion: 'Raise --max-keys, or split the key set.',
    })
    return null
  }

  const entries = []
  let refused = 0
  for (let index = 0; index < value.keys.length; index += 1) {
    const raw = value.keys[index]
    const pointer = `/keys/${index}`
    if (!isPlainObject(raw)) {
      refused += 1
      sink.add({ file, pointer, ruleId: 'jwk-invalid', message: `A key must be an object; this is ${describeValue(raw)}.` })
      continue
    }
    if (Object.keys(raw).length > limits.maxListEntries) {
      refused += 1
      sink.add({
        file,
        pointer,
        ruleId: 'too-many-list-entries',
        message: `This key declares ${Object.keys(raw).length} members, above the maxListEntries limit of ${limits.maxListEntries}; it was refused rather than read in part.`,
        suggestion: 'Raise --max-list-entries, or check that this is a JWK.',
      })
      continue
    }
    entries.push({ index, pointer, raw })
  }

  return { declared: value.keys.length, entries, refused }
}
