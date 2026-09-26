import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CALLBACK,
  clean,
  client,
  cliReport,
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
 * Severity, pinned by the process exit code.
 *
 * The error rules whose runs complete -- nothing about their input is unknown,
 * unsupported or truncated -- make the binary exit 1. Demote any of them to a
 * warning and the same input exits 0: a refusal turned into a green build,
 * which is exactly the drift a table cannot defend against. Three declarations
 * can be edited together; an exit code cannot be edited at all.
 *
 * The warning and info rules are pinned from the other side: each of them alone
 * must exit 0, so promoting one to an error is caught here too.
 *
 * Every expectation below is a literal written at the place it is asserted.
 */

test('a configuration with nothing wrong exits 0 with an empty findings list', async () => {
  const { code, report } = await cliReport(clean())

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 0)
  assert.deepEqual(report.findings, [])
  assert.equal(report.summary.checked, 11, 'three endpoints, two URIs, one key and five settings')
})

test('an issuer the client does not expect exits 1', async () => {
  const { code, report } = await cliReport(fixture({ metadata: metadata({ issuer: 'https://login.example.invalid' }) }))

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(report.profile.issuerMatches, false)
})

test('a key with no key id exits 1', async () => {
  const { code, report } = await cliReport(fixture({ jwks: jwks([rsaKey('good'), rsaKey(undefined)]) }))

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.usableKeys, 1)
})

test('an algorithm the policy does not permit exits 1', async () => {
  const { code, report } = await cliReport(fixture({ jwks: jwks([rsaKey('a'), ecKey('e')]) }))

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a redirect URI the policy does not allow exits 1', async () => {
  const { code, report } = await cliReport(fixture({ client: client({ redirectUris: ['https://app.example.invalid/other'] }) }))

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a provider offering none exits 1', async () => {
  const { code, report } = await cliReport(fixture({
    metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'none'] }),
  }))

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a policy declaring prefix matching exits 1', async () => {
  const { code, report } = await cliReport(fixture({ policy: policy({ redirectUriMatching: 'prefix' }) }))

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a key set too small to stage a rotation exits 1', async () => {
  const { code, report } = await cliReport(fixture({ policy: policy({ minimumKeys: 2 }) }))

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.usableKeys, 1)
})

test('a published private key parameter exits 1', async () => {
  const { code, report } = await cliReport(fixture({ jwks: jwks([rsaKey('a', { d: 'AAAA' })]) }))

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 3)
  assert.equal(report.summary.usableKeys, 0)
})

test('a run whose only findings are warnings exits 0', async () => {
  const origin = await cliReport(fixture({ metadata: metadata({ jwks_uri: 'https://keys.example.invalid/jwks' }) }))
  assert.equal(origin.report.summary.errors, 0, 'this case must raise no error for the exit code to mean anything')
  assert.equal(origin.report.summary.warnings, 1, 'and at least one warning, or it proves nothing')
  assert.equal(origin.report.status, 'pass')
  assert.equal(origin.code, 0)

  const surface = await cliReport(fixture({ metadata: metadata({ id_token_signing_alg_values_supported: ['ES256', 'RS256'] }) }))
  assert.equal(surface.report.summary.errors, 0)
  assert.equal(surface.report.summary.warnings, 1)
  assert.equal(surface.report.status, 'pass')
  assert.equal(surface.code, 0)

  const symmetric = await cliReport(fixture({
    client: client({ idTokenSignedResponseAlg: 'HS256' }),
    metadata: metadata({ id_token_signing_alg_values_supported: ['HS256', 'RS256'] }),
    policy: policy({ allowedIdTokenSigningAlgs: ['HS256', 'RS256'] }),
  }))
  assert.equal(symmetric.report.summary.errors, 0)
  assert.equal(symmetric.report.summary.warnings, 1)
  assert.equal(symmetric.report.status, 'pass')
  assert.equal(symmetric.code, 0)

  const loopback = await cliReport(fixture({
    client: client({ redirectUris: ['http://localhost:8765/cb'] }),
    policy: policy({ allowedRedirectUris: ['http://localhost:8765/cb'] }),
  }))
  assert.equal(loopback.report.summary.errors, 0)
  assert.equal(loopback.report.summary.warnings, 2)
  assert.equal(loopback.report.status, 'pass')
  assert.equal(loopback.code, 0)
})

test('a run whose only findings are information exits 0', async () => {
  const spare = await cliReport(fixture({ policy: policy({ allowedRedirectUris: [CALLBACK, 'https://app.example.invalid/spare'] }) }))
  assert.equal(spare.report.summary.errors, 0)
  assert.equal(spare.report.summary.warnings, 0)
  assert.equal(spare.report.findings.length, 1)
  assert.equal(spare.report.status, 'pass')
  assert.equal(spare.code, 0)

  const member = await cliReport(fixture({ metadata: metadata({ tenant: 'one' }) }))
  assert.equal(member.report.summary.errors, 0)
  assert.equal(member.report.findings.length, 1)
  assert.equal(member.report.status, 'pass')
  assert.equal(member.code, 0)

  const vendor = await cliReport(fixture({ jwks: jwks([rsaKey('a', { vendor: 1 })]) }))
  assert.equal(vendor.report.summary.errors, 0)
  assert.equal(vendor.report.findings.length, 1)
  assert.equal(vendor.report.status, 'pass')
  assert.equal(vendor.code, 0)
})

test('an incomplete run exits 2 and carries a report that is not a pass', async () => {
  const { code, report, stdout } = await cliReport(fixture({ jwks: jwks([rsaKey('modern', { alg: 'BS256' })]) }))

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  // Not "and it is not a pass" -- the line above already says which status it
  // is. What is worth saying here is why: the key this build cannot reason
  // about stayed out of the usable set, so every rotation answer about the set
  // is a floor rather than an answer.
  assert.equal(report.summary.usableKeys, 0)
  assert.equal(report.profile.signingKeys[0].status, 'unknown')
  assert.equal(JSON.parse(stdout).status, 'incomplete', 'stdout is still a report a consumer can parse')
})

test('a configuration error exits 2 with an empty stdout', async () => {
  const missing = await cliRun([])
  assert.equal(missing.code, 2)
  assert.equal(missing.stdout, '')
  assert.equal(missing.stderr.includes('--root is required'), true)

  const unknown = await withRoot(clean(), (root) => cliRun(['--root', root, '--max-key', '3']))
  assert.equal(unknown.code, 2)
  assert.equal(unknown.stdout, '')

  const repeated = await withRoot(clean(), (root) => cliRun(['--root', root, '--policy', 'a.json', '--policy', 'b.json']))
  assert.equal(repeated.code, 2)
  assert.equal(repeated.stdout, '')
  assert.equal(repeated.stderr.includes('--policy was given more than once'), true)
})
