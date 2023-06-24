import assert from 'node:assert/strict'
import test from 'node:test'

import {
  apiReport,
  client,
  findingsFor,
  fixture,
  jwks,
  metadata,
  policy,
  raisedRules,
  rsaKey,
} from './support.mjs'

/**
 * Client settings against the provider's metadata and the deployment's policy:
 * the ID token algorithm, the response types, the token endpoint
 * authentication method and PKCE.
 *
 * "none" is the constant in all of it. A provider that offers it, a client that
 * selects it and a policy that permits it are three separate mistakes, each
 * with its own rule, and none of them is a configuration this tool will call
 * satisfied whatever the policy document says.
 */

test('a provider that offers none fails, whatever the client selected', async () => {
  const report = await apiReport(fixture({
    metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'none'] }),
  }))

  const finding = findingsFor(report, 'alg-none-offered')[0]
  assert.equal(finding.location.pointer, '/id_token_signing_alg_values_supported/1')
  assert.equal(report.status, 'fail')
})

test('a client that selects none accepts an unsigned token', async () => {
  const report = await apiReport(fixture({
    client: client({ idTokenSignedResponseAlg: 'none' }),
    metadata: metadata({ id_token_signing_alg_values_supported: ['none'] }),
    policy: policy({ allowedIdTokenSigningAlgs: ['none'] }),
  }))

  assert.deepEqual(
    raisedRules(report),
    ['alg-none-offered', 'alg-none-permitted', 'alg-none-selected', 'jwk-alg-not-permitted', 'jwks-no-signing-key'],
  )
  assert.equal(report.status, 'fail', 'a policy permitting none does not make none acceptable')
})

test('a policy that permits none is itself the finding', async () => {
  const report = await apiReport(fixture({ policy: policy({ allowedIdTokenSigningAlgs: ['RS256', 'none'] }) }))

  const finding = findingsFor(report, 'alg-none-permitted')[0]
  assert.equal(finding.location.file, 'policy.json')
  assert.equal(finding.location.pointer, '/allowedIdTokenSigningAlgs/1')
  assert.equal(report.status, 'fail')
})

test('an algorithm the policy does not permit fails and names what is permitted', async () => {
  const report = await apiReport(fixture({
    client: client({ idTokenSignedResponseAlg: 'RS512' }),
    metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'RS512'] }),
  }))

  const finding = findingsFor(report, 'alg-not-permitted')[0]
  assert.equal(finding.evidence, 'permitted: RS256')
  assert.equal(report.status, 'fail')
})

test('an algorithm the provider does not offer is a verification that can never run', async () => {
  const report = await apiReport(fixture({
    client: client({ idTokenSignedResponseAlg: 'ES256' }),
    jwks: jwks([rsaKey('signing')]),
    policy: policy({ allowedIdTokenSigningAlgs: ['ES256', 'RS256'] }),
  }))

  assert.equal(findingsFor(report, 'alg-not-offered').length, 1)
  assert.equal(report.status, 'fail')
})

test('an algorithm this build does not implement is unsupported on the client too', async () => {
  const report = await apiReport(fixture({ client: client({ idTokenSignedResponseAlg: 'BS256' }) }))

  assert.equal(findingsFor(report, 'alg-unrecognised')[0].location.file, 'client.json')
  assert.equal(report.profile.algorithms.selected, 'BS256')
  assert.equal(report.status, 'incomplete')
})

test('an algorithm the policy permits and this build does not implement cannot be enforced', async () => {
  const report = await apiReport(fixture({ policy: policy({ allowedIdTokenSigningAlgs: ['RS256', 'BS256'] }) }))

  assert.equal(findingsFor(report, 'alg-unrecognised')[0].location.file, 'policy.json')
  assert.equal(report.status, 'incomplete')
})

test('an offered algorithm the policy does not permit is surface, not a failure', async () => {
  const report = await apiReport(fixture({
    metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'ES256'] }),
  }))

  const finding = findingsFor(report, 'alg-offered-not-permitted')[0]
  assert.equal(finding.severity, 'warning')
  assert.equal(finding.location.pointer, '/id_token_signing_alg_values_supported')
  assert.equal(report.status, 'pass')
})

test('a symmetric algorithm is a warning that says what this tool cannot check', async () => {
  const report = await apiReport(fixture({
    client: client({ idTokenSignedResponseAlg: 'HS256' }),
    metadata: metadata({ id_token_signing_alg_values_supported: ['HS256'] }),
    policy: policy({ allowedIdTokenSigningAlgs: ['HS256'] }),
  }))

  const finding = findingsFor(report, 'alg-symmetric-selected')[0]
  assert.equal(finding.severity, 'warning')
  assert.equal(finding.message.includes('never reads a secret'), true)
  assert.equal(findingsFor(report, 'jwks-selected-alg-unusable').length, 0, 'a shared secret is not expected in a published key set')
})

test('a response type the provider does not list is compared as an exact string', async () => {
  const report = await apiReport(fixture({
    client: client({ responseTypes: ['id_token code'] }),
    policy: policy({ allowedResponseTypes: ['id_token code'] }),
  }))

  const finding = findingsFor(report, 'response-type-not-offered')[0]
  assert.equal(finding.message.includes('spacing and order included'), true)
  assert.equal(report.status, 'fail')
})

test('a response type the policy does not permit is its own rule', async () => {
  const report = await apiReport(fixture({
    client: client({ responseTypes: ['id_token token'] }),
    metadata: metadata({ response_types_supported: ['code', 'id_token token'] }),
  }))

  assert.deepEqual(raisedRules(report), ['response-type-not-permitted'])
  assert.equal(report.status, 'fail')
})

test('an authentication method is checked against the provider and against the policy', async () => {
  const report = await apiReport(fixture({
    client: client({ tokenEndpointAuthMethod: 'client_secret_post' }),
  }))

  assert.deepEqual(raisedRules(report), ['auth-method-not-offered', 'auth-method-not-permitted'])
  assert.equal(report.status, 'fail')
})

test('a provider that does not offer S256 fails a policy that requires PKCE', async () => {
  const without = metadata()
  delete without.code_challenge_methods_supported
  const report = await apiReport(fixture({ metadata: without }))

  const finding = findingsFor(report, 'pkce-s256-not-offered')[0]
  assert.equal(finding.message.includes('absence is not evidence of support'), true)
  assert.equal(report.status, 'fail')
})

test('a client that uses plain PKCE fails a policy that requires S256', async () => {
  const report = await apiReport(fixture({ client: client({ pkceMethod: 'plain' }) }))

  assert.equal(findingsFor(report, 'pkce-not-s256')[0].message.includes('"plain"'), true)
  assert.equal(report.status, 'fail')
})

test('a policy that does not require PKCE checks nothing about it', async () => {
  const report = await apiReport(fixture({
    client: client({ pkceMethod: 'plain' }),
    policy: policy({ requirePkceS256: false }),
  }))

  assert.deepEqual(raisedRules(report), [])
  assert.equal(report.summary.settings, 4, 'the PKCE setting is not counted as checked when it is not checked')
})

test('a policy field that is absent leaves its check unperformed and says so', async () => {
  const partial = policy()
  delete partial.allowedIdTokenSigningAlgs
  const report = await apiReport(fixture({ policy: partial }))

  assert.equal(findingsFor(report, 'policy-field-missing').length, 1)
  assert.deepEqual(report.profile.algorithms.permitted, [], 'nothing is invented for a policy nobody wrote')
  assert.equal(report.status, 'fail')
})
