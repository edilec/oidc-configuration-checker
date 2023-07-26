import assert from 'node:assert/strict'
import test from 'node:test'

import { checkOidcConfiguration } from '../src/index.mjs'
import {
  CALLBACK,
  RSA_2048_NEXT,
  apiReport,
  clean,
  client,
  cliReport,
  ecKey,
  fixture,
  jwks,
  metadata,
  policy,
  raisedRules,
  rsaKey,
  withRoot,
} from './support.mjs'

/**
 * Every reason a run is `incomplete`, one case each.
 *
 * `src/index.mjs` numbers seven places where `state.incomplete` is set. Deleting
 * any one of them turns its case below from `incomplete` into `fail` -- the
 * findings are error-severity, so the suite would otherwise stay green while a
 * run that obtained less evidence than it was asked for started calling itself
 * a verdict. Each case therefore asserts the status and the exit code as
 * literals, and says which flag it is standing on.
 *
 * The distinction being defended is the whole point of the status: `fail` means
 * "checked, and wrong"; `incomplete` means "not checked". A tool that reports
 * the first when it means the second is telling you it looked.
 */

test('(1) an input that could not be reached leaves the run incomplete', async () => {
  const files = clean()
  delete files['jwks.json']
  const { code, report } = await cliReport(files)

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.deepEqual(raisedRules(report), ['input-unreadable'])
})

test('(2) bytes that could not be decoded or parsed leave the run incomplete', async () => {
  const undecodable = await cliReport({ ...clean(), 'metadata.json': new Uint8Array([0xc3, 0x28]) })
  assert.equal(undecodable.report.status, 'incomplete')
  assert.equal(undecodable.code, 2)

  const unparseable = await cliReport({ ...clean(), 'metadata.json': '{ "issuer": }' })
  assert.equal(unparseable.report.status, 'incomplete')
  assert.equal(unparseable.code, 2)
})

test('(3) a document this build cannot take leaves the run incomplete', async () => {
  const { code, report } = await cliReport(fixture({ policy: { ...policy(), allowedScopes: [] } }))

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.deepEqual(raisedRules(report), ['policy-invalid'])
})

test('(4) a member refused for its shape leaves the run incomplete', async () => {
  const { code, report } = await cliReport(fixture({
    metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 7] }),
  }))

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(report.profile.algorithms.offered.length, 1, 'the list was read in part, which is why this is not a verdict')
})

test('(5) an algorithm or key type this build does not implement leaves the run incomplete', async () => {
  for (const keys of [
    [rsaKey('a', { alg: 'BS256' })],
    [{ kty: 'Kyber768', kid: 'pq', alg: 'RS256' }],
    [(() => { const key = rsaKey('a'); delete key.alg; return key })()],
  ]) {
    const { code, report } = await cliReport(fixture({ jwks: jwks(keys) }))
    assert.equal(report.status, 'incomplete')
    assert.equal(code, 2)
    assert.equal(report.profile.signingKeys[0].status, 'unknown')
  }

  const setting = await cliReport(fixture({ client: client({ idTokenSignedResponseAlg: 'BS256' }) }))
  assert.equal(setting.report.status, 'incomplete')
  assert.equal(setting.code, 2)
})

test('(5) a redirect URI that could not be read, or that holds a wildcard, leaves the run incomplete', async () => {
  const unreadable = await cliReport(fixture({ client: client({ redirectUris: [CALLBACK, 'not a uri'] }) }))
  assert.equal(unreadable.report.status, 'incomplete')
  assert.equal(unreadable.code, 2)

  const wildcard = await cliReport(fixture({ policy: policy({ allowedRedirectUris: [CALLBACK, 'https://app.example.invalid/*'] }) }))
  assert.equal(wildcard.report.status, 'incomplete')
  assert.equal(wildcard.code, 2)
  assert.equal(wildcard.report.profile.redirectUris[0].status, 'allowlisted', 'the entries that were read were still compared')
})

test('(6) the vacuous pass is refused explicitly, not by accident', async () => {
  const { code, report } = await cliReport({
    'metadata.json': {},
    'client.json': { schemaVersion: '1' },
    'policy.json': { schemaVersion: '1' },
    'jwks.json': { keys: [] },
  })

  assert.equal(report.summary.checked, 0)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(
    report.findings.some((finding) => finding.ruleId === 'no-checks-performed'),
    true,
    'both halves are needed: the flag stops the pass and the finding says why',
  )
})

test('(7) a run that stopped early leaves the run incomplete', async () => {
  let now = 0
  const report = await withRoot(fixture({ jwks: jwks([rsaKey('a'), rsaKey('b', { n: RSA_2048_NEXT.n })]) }), (root) =>
    checkOidcConfiguration({ root, limits: { maxRuntimeMs: 5 }, clock: () => { now += 3; return now } }))

  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.keys, 0)
  assert.deepEqual(report.profile.signingKeys, [])
})

test('a run that is incomplete for one reason is still a verdict about everything else it read', async () => {
  const report = await apiReport(fixture({
    metadata: metadata({ issuer: 'https://login.example.invalid' }),
    jwks: jwks([rsaKey('a', { alg: 'BS256' })]),
  }))

  assert.equal(report.status, 'incomplete')
  assert.equal(report.profile.issuerMatches, false, 'the issuer was compared and did not match')
  assert.equal(
    report.findings.some((finding) => finding.ruleId === 'issuer-mismatch'),
    true,
    'an incomplete run still reports what it did establish',
  )
})

test('a control the provider published no evidence about is incomplete, and exits 2', async () => {
  // The one optional discovery list the settings checks compare against. An
  // absent `token_endpoint_auth_methods_supported` used to skip the comparison
  // silently and leave the run reporting `pass` with the setting still counted
  // -- evidence never obtained, satisfying a control.
  const without = metadata()
  delete without.token_endpoint_auth_methods_supported
  const { code, report } = await cliReport(fixture({ metadata: without }))

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.deepEqual(raisedRules(report), ['auth-method-support-unknown'])
})

test('nothing that reached an unknown is counted as usable, checked or satisfied', async () => {
  const report = await apiReport(fixture({
    jwks: jwks([rsaKey('known'), rsaKey('unknown', { alg: 'BS256', n: RSA_2048_NEXT.n }), ecKey('banned')]),
  }))

  assert.equal(report.summary.keys, 3)
  assert.equal(report.summary.usableKeys, 1)
  assert.deepEqual(report.profile.signingKeys.map((row) => [row.kid, row.status]), [
    ['banned', 'not-permitted'],
    ['known', 'usable'],
    ['unknown', 'unknown'],
  ])
  assert.equal(report.status, 'incomplete')
})
