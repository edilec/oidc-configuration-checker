import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CALLBACK,
  RSA_1024,
  RSA_2048_NEXT,
  clean,
  client,
  cliRun,
  ecKey,
  fixture,
  jwks,
  metadata,
  policy,
  rsaKey,
  withRoot,
} from './support.mjs'

/**
 * Every rule in the catalog, driven through the real binary, with the severity
 * word the human report actually printed asserted as a literal string.
 *
 * This file shares no map, no table import and no parameterised expectation
 * with the source. Each line below is written out where it is asserted, so a
 * coordinated edit of the severity table *and* the documentation *and* any
 * expected-value map elsewhere still leaves these assertions failing: the word
 * in the printed line comes from the run.
 *
 * Exit codes pin the same thing from the other side in
 * `test/severity-exit.test.mjs`, for the rules whose runs complete. They cannot
 * pin the rules that make a run incomplete -- those exit 2 whatever their
 * severity -- which is exactly why the printed word is pinned here for all of
 * them.
 */

/** Run the real binary over a temporary root, with the human report on stderr. */
async function human(files, extraArgs = []) {
  return withRoot(files, async (root) => {
    const result = await cliRun(['--root', root, ...extraArgs])
    return { ...result, report: result.stdout === '' ? null : JSON.parse(result.stdout) }
  })
}

const drop = (document, ...keys) => {
  const copy = { ...document }
  for (const key of keys) delete copy[key]
  return copy
}

test('the algorithm rules print the severity word they carry', async () => {
  const offered = await human(fixture({ metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'none'] }) }))
  assert.equal(offered.stderr.includes('ERROR   metadata.json/id_token_signing_alg_values_supported/1 alg-none-offered '), true)
  assert.equal(offered.report.summary.errors, 1)

  const permitted = await human(fixture({ policy: policy({ allowedIdTokenSigningAlgs: ['RS256', 'none'] }) }))
  assert.equal(permitted.stderr.includes('ERROR   policy.json/allowedIdTokenSigningAlgs/1 alg-none-permitted '), true)
  assert.equal(permitted.report.summary.errors, 1)

  const selected = await human(fixture({ client: client({ idTokenSignedResponseAlg: 'none' }) }))
  assert.equal(selected.stderr.includes('ERROR   client.json/idTokenSignedResponseAlg alg-none-selected '), true)
  assert.equal(selected.report.summary.errors, 1)

  const notOffered = await human(fixture({
    client: client({ idTokenSignedResponseAlg: 'ES256' }),
    policy: policy({ allowedIdTokenSigningAlgs: ['ES256', 'RS256'] }),
    jwks: jwks([rsaKey('r'), ecKey('e')]),
  }))
  assert.equal(notOffered.stderr.includes('ERROR   client.json/idTokenSignedResponseAlg alg-not-offered '), true)
  assert.equal(notOffered.report.summary.errors, 1)

  const notPermitted = await human(fixture({
    client: client({ idTokenSignedResponseAlg: 'ES256' }),
    metadata: metadata({ id_token_signing_alg_values_supported: ['ES256', 'RS256'] }),
  }))
  assert.equal(notPermitted.stderr.includes('ERROR   client.json/idTokenSignedResponseAlg alg-not-permitted '), true)
  assert.equal(notPermitted.report.summary.errors, 2, 'and the key set then carries nothing that can verify it')

  const unrecognised = await human(fixture({ client: client({ idTokenSignedResponseAlg: 'BS256' }) }))
  assert.equal(unrecognised.stderr.includes('ERROR   client.json/idTokenSignedResponseAlg alg-unrecognised '), true)
  assert.equal(unrecognised.report.summary.errors, 1)
})

test('the two algorithm rules that are not errors print the words they carry', async () => {
  const surface = await human(fixture({ metadata: metadata({ id_token_signing_alg_values_supported: ['ES256', 'RS256'] }) }))
  assert.equal(surface.stderr.includes('WARNING metadata.json/id_token_signing_alg_values_supported alg-offered-not-permitted '), true)
  assert.equal(surface.report.summary.errors, 0)
  assert.equal(surface.report.summary.warnings, 1)
  assert.equal(surface.code, 0)

  const symmetric = await human(fixture({
    client: client({ idTokenSignedResponseAlg: 'HS256' }),
    metadata: metadata({ id_token_signing_alg_values_supported: ['HS256', 'RS256'] }),
    policy: policy({ allowedIdTokenSigningAlgs: ['HS256', 'RS256'] }),
  }))
  assert.equal(symmetric.stderr.includes('WARNING client.json/idTokenSignedResponseAlg alg-symmetric-selected '), true)
  assert.equal(symmetric.report.summary.errors, 0)
  assert.equal(symmetric.report.summary.warnings, 1)
  assert.equal(symmetric.code, 0)
})

test('the issuer and endpoint rules print the severity word they carry', async () => {
  const mismatch = await human(fixture({ metadata: metadata({ issuer: 'https://login.example.invalid' }) }))
  assert.equal(mismatch.stderr.includes('ERROR   client.json/expectedIssuer issuer-mismatch '), true)
  assert.equal(mismatch.report.summary.errors, 1)

  const slash = await human(fixture({ client: client({ expectedIssuer: 'https://id.example.invalid/' }) }))
  assert.equal(slash.stderr.includes('ERROR   client.json/expectedIssuer issuer-trailing-slash '), true)
  assert.equal(slash.report.summary.errors, 1)

  const query = await human(fixture({
    metadata: metadata({ issuer: 'https://id.example.invalid?t=1' }),
    client: client({ expectedIssuer: 'https://id.example.invalid?t=1' }),
  }))
  assert.equal(query.stderr.includes('ERROR   metadata.json/issuer issuer-invalid '), true)
  assert.equal(query.report.summary.errors, 1)

  const insecure = await human(fixture({
    metadata: metadata({ issuer: 'http://id.example.invalid' }),
    client: client({ expectedIssuer: 'http://id.example.invalid' }),
  }))
  assert.equal(insecure.stderr.includes('ERROR   metadata.json/issuer issuer-not-https '), true)
  assert.equal(insecure.report.summary.errors, 4, 'the three endpoints inherit the issuer transport')

  const endpoint = await human(fixture({ metadata: metadata({ token_endpoint: 'http://id.example.invalid/token' }) }))
  assert.equal(endpoint.stderr.includes('ERROR   metadata.json/token_endpoint endpoint-not-https '), true)
  assert.equal(endpoint.report.summary.errors, 1)

  const unreadable = await human(fixture({ metadata: metadata({ userinfo_endpoint: 'not a url' }) }))
  assert.equal(unreadable.stderr.includes('ERROR   metadata.json/userinfo_endpoint endpoint-invalid '), true)
  assert.equal(unreadable.report.summary.errors, 1)

  const origin = await human(fixture({ metadata: metadata({ jwks_uri: 'https://keys.example.invalid/jwks' }) }))
  assert.equal(origin.stderr.includes('WARNING metadata.json/jwks_uri endpoint-origin-differs '), true)
  assert.equal(origin.report.summary.errors, 0)
  assert.equal(origin.report.summary.warnings, 1)
  assert.equal(origin.code, 0)

  const missing = await human(fixture({ metadata: drop(metadata(), 'jwks_uri') }))
  assert.equal(missing.stderr.includes('ERROR   metadata.json metadata-field-missing '), true)
  assert.equal(missing.report.summary.errors, 1)

  const shape = await human(fixture({ metadata: metadata({ subject_types_supported: 'public' }) }))
  assert.equal(shape.stderr.includes('ERROR   metadata.json/subject_types_supported metadata-invalid '), true)
  assert.equal(shape.report.summary.errors, 1)

  const extension = await human(fixture({ metadata: metadata({ tenant: 'one' }) }))
  assert.equal(extension.stderr.includes('INFO    metadata.json/tenant metadata-key-unknown '), true)
  assert.equal(extension.report.summary.errors, 0)
  assert.equal(extension.code, 0)
})

test('the redirect rules print the severity word they carry', async () => {
  const prefix = await human(fixture({ policy: policy({ redirectUriMatching: 'prefix' }) }))
  assert.equal(prefix.stderr.includes('ERROR   policy.json/redirectUriMatching redirect-matching-not-exact '), true)
  assert.equal(prefix.report.summary.errors, 1)

  const unlisted = await human(fixture({ client: client({ redirectUris: ['https://app.example.invalid/other'] }) }))
  assert.equal(unlisted.stderr.includes('ERROR   client.json/redirectUris/0 redirect-uri-not-allowlisted '), true)
  assert.equal(unlisted.report.summary.errors, 1)

  const repeated = await human(fixture({ client: client({ redirectUris: [CALLBACK, CALLBACK] }) }))
  assert.equal(repeated.stderr.includes('ERROR   client.json/redirectUris/1 redirect-uri-duplicate '), true)
  assert.equal(repeated.report.summary.errors, 1)

  const fragment = await human(fixture({
    client: client({ redirectUris: [`${CALLBACK}#x`] }),
    policy: policy({ allowedRedirectUris: [`${CALLBACK}#x`] }),
  }))
  assert.equal(fragment.stderr.includes('ERROR   client.json/redirectUris/0 redirect-uri-fragment '), true)
  assert.equal(fragment.report.summary.errors, 2, 'the policy entry carries the same fragment')

  const userinfo = await human(fixture({
    client: client({ redirectUris: ['https://u@app.example.invalid/cb'] }),
    policy: policy({ allowedRedirectUris: ['https://u@app.example.invalid/cb'] }),
  }))
  assert.equal(userinfo.stderr.includes('ERROR   client.json/redirectUris/0 redirect-uri-userinfo '), true)
  assert.equal(userinfo.report.summary.errors, 2)

  const scheme = await human(fixture({
    client: client({ redirectUris: ['http://app.example.invalid/cb'] }),
    policy: policy({ allowedRedirectUris: ['http://app.example.invalid/cb'] }),
  }))
  assert.equal(scheme.stderr.includes('ERROR   client.json/redirectUris/0 redirect-uri-insecure-scheme '), true)
  assert.equal(scheme.report.summary.errors, 2)

  const wildcard = await human(fixture({ policy: policy({ allowedRedirectUris: [CALLBACK, 'https://app.example.invalid/*'] }) }))
  assert.equal(wildcard.stderr.includes('ERROR   policy.json/allowedRedirectUris/1 redirect-uri-wildcard '), true)
  assert.equal(wildcard.report.summary.errors, 1)

  const unreadable = await human(fixture({ client: client({ redirectUris: ['/cb'] }) }))
  assert.equal(unreadable.stderr.includes('ERROR   client.json/redirectUris/0 redirect-uri-invalid '), true)
  assert.equal(unreadable.report.summary.errors, 1)

  const named = await human(fixture({
    client: client({ redirectUris: ['http://localhost:8765/cb'] }),
    policy: policy({ allowedRedirectUris: ['http://localhost:8765/cb'] }),
  }))
  assert.equal(named.stderr.includes('WARNING client.json/redirectUris/0 redirect-uri-loopback-hostname '), true)
  assert.equal(named.report.summary.errors, 0)
  assert.equal(named.report.summary.warnings, 2)
  assert.equal(named.code, 0)

  const spare = await human(fixture({ policy: policy({ allowedRedirectUris: [CALLBACK, 'https://app.example.invalid/spare'] }) }))
  assert.equal(spare.stderr.includes('INFO    policy.json/allowedRedirectUris/1 redirect-uri-unused '), true)
  assert.equal(spare.report.summary.errors, 0)
  assert.equal(spare.code, 0)
})

test('the client and policy setting rules print the severity word they carry', async () => {
  const responseOffered = await human(fixture({
    client: client({ responseTypes: ['code id_token'] }),
    policy: policy({ allowedResponseTypes: ['code id_token'] }),
  }))
  assert.equal(responseOffered.stderr.includes('ERROR   client.json/responseTypes response-type-not-offered '), true)
  assert.equal(responseOffered.report.summary.errors, 1)

  const responsePermitted = await human(fixture({
    client: client({ responseTypes: ['id_token'] }),
    metadata: metadata({ response_types_supported: ['code', 'id_token'] }),
  }))
  assert.equal(responsePermitted.stderr.includes('ERROR   client.json/responseTypes response-type-not-permitted '), true)
  assert.equal(responsePermitted.report.summary.errors, 1)

  const methodOffered = await human(fixture({
    client: client({ tokenEndpointAuthMethod: 'client_secret_basic' }),
    policy: policy({ allowedTokenEndpointAuthMethods: ['client_secret_basic'] }),
  }))
  assert.equal(methodOffered.stderr.includes('ERROR   client.json/tokenEndpointAuthMethod auth-method-not-offered '), true)
  assert.equal(methodOffered.report.summary.errors, 1)

  const methodPermitted = await human(fixture({
    client: client({ tokenEndpointAuthMethod: 'client_secret_basic' }),
    metadata: metadata({ token_endpoint_auth_methods_supported: ['client_secret_basic'] }),
  }))
  assert.equal(methodPermitted.stderr.includes('ERROR   client.json/tokenEndpointAuthMethod auth-method-not-permitted '), true)
  assert.equal(methodPermitted.report.summary.errors, 1)

  const pkceClient = await human(fixture({ client: client({ pkceMethod: 'plain' }) }))
  assert.equal(pkceClient.stderr.includes('ERROR   client.json/pkceMethod pkce-not-s256 '), true)
  assert.equal(pkceClient.report.summary.errors, 1)

  const pkceProvider = await human(fixture({ metadata: metadata({ code_challenge_methods_supported: ['plain'] }) }))
  assert.equal(pkceProvider.stderr.includes('ERROR   metadata.json/code_challenge_methods_supported pkce-s256-not-offered '), true)
  assert.equal(pkceProvider.report.summary.errors, 1)

  const clientMissing = await human(fixture({ client: drop(client(), 'clientId') }))
  assert.equal(clientMissing.stderr.includes('ERROR   client.json client-field-missing '), true)
  assert.equal(clientMissing.report.summary.errors, 1)

  const clientStray = await human(fixture({ client: { ...client(), extra: 1 } }))
  assert.equal(clientStray.stderr.includes('ERROR   client.json client-invalid '), true)
  assert.equal(clientStray.report.summary.errors, 1)

  const policyMissing = await human(fixture({ policy: drop(policy(), 'minimumKeys') }))
  assert.equal(policyMissing.stderr.includes('ERROR   policy.json policy-field-missing '), true)
  assert.equal(policyMissing.report.summary.errors, 1)

  const policyStray = await human(fixture({ policy: { ...policy(), extra: 1 } }))
  assert.equal(policyStray.stderr.includes('ERROR   policy.json policy-invalid '), true)
  assert.equal(policyStray.report.summary.errors, 1)

  const version = await human(fixture({ policy: policy({ schemaVersion: '2' }) }))
  assert.equal(version.stderr.includes('ERROR   policy.json/schemaVersion schema-version-unsupported '), true)
  assert.equal(version.report.summary.errors, 1)
})

test('the key rules print the severity word they carry', async () => {
  const noKid = await human(fixture({ jwks: jwks([rsaKey('good'), rsaKey(undefined, { n: RSA_2048_NEXT.n })]) }))
  assert.equal(noKid.stderr.includes('ERROR   jwks.json/keys/1 jwk-kid-missing '), true)
  assert.equal(noKid.report.summary.errors, 1)

  const badKid = await human(fixture({ jwks: jwks([rsaKey('-bad')]) }))
  assert.equal(badKid.stderr.includes('ERROR   jwks.json/keys/0/kid jwk-kid-invalid '), true)
  assert.equal(badKid.report.summary.errors, 3, 'and then nothing usable is left in the set')

  const twice = await human(fixture({ jwks: jwks([rsaKey('same'), rsaKey('same', { n: RSA_2048_NEXT.n })]) }))
  assert.equal(twice.stderr.includes('ERROR   jwks.json/keys/1/kid jwk-kid-duplicate '), true)
  assert.equal(twice.report.summary.errors, 1)

  const noAlg = await human(fixture({ jwks: jwks([drop(rsaKey('a'), 'alg')]) }))
  assert.equal(noAlg.stderr.includes('ERROR   jwks.json/keys/0 jwk-alg-undeclared '), true)
  assert.equal(noAlg.report.summary.errors, 3)

  const algNone = await human(fixture({ jwks: jwks([rsaKey('a', { alg: 'none' })]) }))
  assert.equal(algNone.stderr.includes('ERROR   jwks.json/keys/0/alg jwk-alg-none '), true)
  assert.equal(algNone.report.summary.errors, 3)

  const algUnknown = await human(fixture({ jwks: jwks([rsaKey('a', { alg: 'BS256' })]) }))
  assert.equal(algUnknown.stderr.includes('ERROR   jwks.json/keys/0/alg jwk-alg-unrecognised '), true)
  assert.equal(algUnknown.report.summary.errors, 3)

  const algBanned = await human(fixture({ jwks: jwks([rsaKey('a'), ecKey('e')]) }))
  assert.equal(algBanned.stderr.includes('ERROR   jwks.json/keys/1/alg jwk-alg-not-permitted '), true)
  assert.equal(algBanned.report.summary.errors, 1)

  const pairing = await human(fixture({ jwks: jwks([ecKey('e', { alg: 'RS256' })]) }))
  assert.equal(pairing.stderr.includes('ERROR   jwks.json/keys/0/alg jwk-alg-key-mismatch '), true)
  assert.equal(pairing.report.summary.errors, 3)

  const curve = await human(fixture({
    jwks: jwks([rsaKey('r'), ecKey('e', { crv: 'P-384' })]),
    policy: policy({ allowedIdTokenSigningAlgs: ['ES256', 'RS256'] }),
  }))
  assert.equal(curve.stderr.includes('ERROR   jwks.json/keys/1/crv jwk-curve-mismatch '), true)
  assert.equal(curve.report.summary.errors, 2, 'and the coordinate no longer fits the curve it declares')

  const shape = await human(fixture({ jwks: jwks([rsaKey('a', { use: 'signing' })]) }))
  assert.equal(shape.stderr.includes('ERROR   jwks.json/keys/0/use jwk-invalid '), true)
  assert.equal(shape.report.summary.errors, 3)

  const kty = await human(fixture({ jwks: jwks([rsaKey('good'), { kty: 'Kyber', kid: 'pq', alg: 'RS256' }]) }))
  assert.equal(kty.stderr.includes('ERROR   jwks.json/keys/1/kty jwk-kty-unsupported '), true)
  assert.equal(kty.report.summary.errors, 1)

  const priv = await human(fixture({ jwks: jwks([rsaKey('a', { d: 'AAAA' })]) }))
  assert.equal(priv.stderr.includes('ERROR   jwks.json/keys/0 jwk-private-material '), true)
  assert.equal(priv.report.summary.errors, 3)

  const short = await human(fixture({ jwks: jwks([rsaKey('a', { n: RSA_1024.n, e: RSA_1024.e })]) }))
  assert.equal(short.stderr.includes('ERROR   jwks.json/keys/0/n jwk-rsa-modulus-short '), true)
  assert.equal(short.report.summary.errors, 3)

  const empty = await human(fixture({ jwks: jwks([]) }))
  assert.equal(empty.stderr.includes('ERROR   jwks.json/keys jwks-no-signing-key '), true)
  assert.equal(empty.report.summary.errors, 2)

  const unusable = await human(fixture({
    jwks: jwks([ecKey('e')]),
    policy: policy({ allowedIdTokenSigningAlgs: ['ES256', 'RS256'] }),
  }))
  assert.equal(unusable.stderr.includes('ERROR   jwks.json/keys jwks-selected-alg-unusable '), true)
  assert.equal(unusable.report.summary.errors, 1)

  const tooFew = await human(fixture({ policy: policy({ minimumKeys: 2 }) }))
  assert.equal(tooFew.stderr.includes('ERROR   jwks.json/keys jwks-too-few-keys '), true)
  assert.equal(tooFew.report.summary.errors, 1)

  const extension = await human(fixture({ jwks: jwks([rsaKey('a', { vendor: 1 })]) }))
  assert.equal(extension.stderr.includes('INFO    jwks.json/keys/0/vendor jwk-member-unknown '), true)
  assert.equal(extension.report.summary.errors, 0)
  assert.equal(extension.code, 0)

  const stray = await human(fixture({ jwks: { keys: [rsaKey('a')], extra: 1 } }))
  assert.equal(stray.stderr.includes('ERROR   jwks.json document-invalid '), true)
  assert.equal(stray.report.summary.errors, 1)
})

test('the input and limit rules print the severity word they carry', async () => {
  const notJson = await human({ ...clean(), 'policy.json': '{' })
  assert.equal(notJson.stderr.includes('ERROR   policy.json input-not-json '), true)
  assert.equal(notJson.report.summary.errors, 1)

  const notUtf8 = await human({ ...clean(), 'policy.json': new Uint8Array([0xff]) })
  assert.equal(notUtf8.stderr.includes('ERROR   policy.json input-not-utf8 '), true)
  assert.equal(notUtf8.report.summary.errors, 1)

  const missing = await human(drop(clean(), 'policy.json'))
  assert.equal(missing.stderr.includes('ERROR   policy.json input-unreadable '), true)
  assert.equal(missing.report.summary.errors, 1)

  const large = await human(clean(), ['--max-file-bytes', '60'])
  assert.equal(large.stderr.includes('ERROR   client.json input-too-large '), true)
  assert.equal(large.report.summary.errors, 4)

  const algs = await human(
    fixture({ metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'ES256'] }) }),
    ['--max-algorithms', '1'],
  )
  assert.equal(algs.stderr.includes('ERROR   metadata.json/id_token_signing_alg_values_supported too-many-algorithms '), true)
  assert.equal(algs.report.summary.errors, 1)

  const keys = await human(fixture({ jwks: jwks([rsaKey('a'), rsaKey('b', { n: RSA_2048_NEXT.n })]) }), ['--max-keys', '1'])
  assert.equal(keys.stderr.includes('ERROR   jwks.json/keys too-many-keys '), true)
  assert.equal(keys.report.summary.errors, 1)

  const uris = await human(
    fixture({ client: client({ redirectUris: [CALLBACK, 'https://a.example.invalid/2'] }) }),
    ['--max-redirect-uris', '1'],
  )
  assert.equal(uris.stderr.includes('ERROR   client.json/redirectUris too-many-redirect-uris '), true)
  assert.equal(uris.report.summary.errors, 1)

  const entries = await human(fixture({ policy: policy({ allowedResponseTypes: ['code', 'id_token'] }) }), ['--max-list-entries', '1'])
  assert.equal(entries.stderr.includes('ERROR   policy.json/allowedResponseTypes too-many-list-entries '), true)
  assert.equal(entries.report.summary.errors, 4, 'the key set is refused under the same limit')

  const members = await human(clean(), ['--max-metadata-keys', '3'])
  assert.equal(members.stderr.includes('ERROR   metadata.json too-many-metadata-keys '), true)
  assert.equal(members.report.summary.errors, 1)

  const findings = await human(
    fixture({ client: client({ redirectUris: ['https://a.example.invalid/1', 'https://a.example.invalid/2', 'https://a.example.invalid/3'] }) }),
    ['--max-findings', '2'],
  )
  assert.equal(findings.stderr.includes('ERROR   policy.json too-many-findings '), true)
  assert.equal(findings.report.summary.errors, 2)
})

test('the two rules that need a driven clock or a planted link print their word too', async () => {
  // The time budget is reached with a clock that advances on every reading, and
  // the confinement rule with a document that resolves out of the tree. Both
  // are exercised for behaviour in their own files; here it is the word.
  const { checkOidcConfiguration } = await import('../src/index.mjs')
  const { formatReport } = await import('../src/index.mjs')

  let now = 0
  const budget = await withRoot(fixture({ jwks: jwks([rsaKey('a'), rsaKey('b', { n: RSA_2048_NEXT.n })]) }), (root) =>
    checkOidcConfiguration({ root, limits: { maxRuntimeMs: 5 }, clock: () => { now += 3; return now } }))
  assert.equal(formatReport(budget).includes('ERROR   jwks.json time-budget-exceeded '), true)
  assert.equal(budget.summary.errors, 1)

  const { mkdtemp, rm, symlink, writeFile } = await import('node:fs/promises')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const outside = await mkdtemp(join(tmpdir(), 'oidc-outside-'))
  try {
    await writeFile(join(outside, 'policy.json'), '{}')
    const escaped = await withRoot(drop(clean(), 'policy.json'), async (root) => {
      await symlink(join(outside, 'policy.json'), join(root, 'policy.json'))
      return checkOidcConfiguration({ root })
    })
    assert.equal(formatReport(escaped).includes('ERROR   policy.json path-escapes-root '), true)
    assert.equal(escaped.summary.errors, 1)
  } finally {
    await rm(outside, { recursive: true, force: true })
  }
})

test('the vacuous pass is refused with an error, and the report says nothing was checked', async () => {
  const vacuous = await human({
    'metadata.json': {},
    'client.json': { schemaVersion: '1' },
    'policy.json': { schemaVersion: '1' },
    'jwks.json': { keys: [] },
  })

  assert.equal(vacuous.stderr.includes('ERROR   client.json no-checks-performed '), true)
  assert.equal(vacuous.report.summary.checked, 0)
  assert.equal(vacuous.report.status, 'incomplete')
  assert.equal(vacuous.code, 2)
})
