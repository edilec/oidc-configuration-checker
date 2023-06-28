import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_LIMITS, HARD_LIMITS, checkOidcConfiguration, validateLimits } from '../src/index.mjs'
import {
  CALLBACK,
  apiReport,
  clean,
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
 * Limits, each enforced and each reported by name.
 *
 * Every case asserts three things together: the finding names the limit, the
 * run is `incomplete`, and the thing over the limit contributed nothing. A
 * limit that silently truncated would satisfy the first two on its own.
 */

test('every documented limit has a cap, and the cap is not below the default', () => {
  assert.deepEqual(Object.keys(DEFAULT_LIMITS), Object.keys(HARD_LIMITS))
  for (const [name, value] of Object.entries(DEFAULT_LIMITS)) {
    assert.equal(HARD_LIMITS[name] >= value, true, name)
  }
})

test('an unknown limit throws rather than being ignored', () => {
  assert.throws(() => validateLimits({ maxKey: 1 }), /Unknown limit "maxKey"/)
  assert.throws(() => validateLimits({ maxKeys: 0 }), /between 1 and/)
  assert.throws(() => validateLimits({ maxKeys: 1.5 }), /between 1 and/)
  assert.throws(() => validateLimits({ maxKeys: HARD_LIMITS.maxKeys + 1 }), /between 1 and/)
  assert.throws(() => validateLimits('maxKeys=1'), /limits must be an object/)
})

test('a limit a caller lowers is the limit that is enforced', () => {
  assert.equal(validateLimits({ maxKeys: 3 }).maxKeys, 3)
  assert.equal(validateLimits({}).maxKeys, DEFAULT_LIMITS.maxKeys)
})

test('a file above the byte limit is not read', async () => {
  const report = await apiReport(clean(), { limits: { maxFileBytes: 40 } })

  const findings = findingsFor(report, 'input-too-large')
  assert.equal(findings.length, 4, 'all four documents, each named')
  assert.equal(findings[0].message.includes('maxFileBytes limit of 40'), true)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 0)
})

test('a key set above the key limit compiles nothing rather than a prefix', async () => {
  const report = await apiReport(
    fixture({ jwks: jwks([rsaKey('a'), rsaKey('b'), rsaKey('c')]) }),
    { limits: { maxKeys: 2 } },
  )

  assert.equal(findingsFor(report, 'too-many-keys')[0].message.includes('maxKeys limit of 2'), true)
  assert.equal(report.summary.keys, 0, 'nothing was read from it')
  assert.equal(report.status, 'incomplete')
})

test('a redirect list above its limit is refused whole', async () => {
  const report = await apiReport(
    fixture({ client: client({ redirectUris: [CALLBACK, 'https://app.example.invalid/b', 'https://app.example.invalid/c'] }) }),
    { limits: { maxRedirectUris: 2 } },
  )

  assert.equal(findingsFor(report, 'too-many-redirect-uris')[0].location.pointer, '/redirectUris')
  assert.equal(report.summary.redirectUris, 0)
  assert.equal(report.status, 'incomplete')
})

test('an algorithm list above its limit is refused whole', async () => {
  const report = await apiReport(
    fixture({ metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'] }) }),
    { limits: { maxAlgorithms: 2 } },
  )

  assert.equal(findingsFor(report, 'too-many-algorithms').length, 1)
  assert.deepEqual(report.profile.algorithms.offered, [], 'a refused list is empty, never partly read')
  assert.equal(report.status, 'incomplete')
})

test('a discovery document with more members than the limit is not read', async () => {
  const wide = metadata()
  for (let index = 0; index < 20; index += 1) wide[`extension_${index}`] = index
  const report = await apiReport(fixture({ metadata: wide }), { limits: { maxMetadataKeys: 10 } })

  assert.equal(findingsFor(report, 'too-many-metadata-keys').length, 1)
  assert.equal(report.profile.issuer, null)
  assert.equal(report.status, 'incomplete')
})

test('any other list above its limit is refused whole, including one key with too many members', async () => {
  const listed = await apiReport(
    fixture({ policy: policy({ allowedResponseTypes: ['code', 'id_token', 'code id_token'] }) }),
    { limits: { maxListEntries: 2 } },
  )
  // The key set is refused under the same limit, so the policy finding is
  // picked out by name rather than by position.
  const policyFinding = findingsFor(listed, 'too-many-list-entries').find((finding) => finding.location.file === 'policy.json')
  assert.equal(policyFinding.location.pointer, '/allowedResponseTypes')

  const wideKey = await apiReport(
    fixture({ jwks: jwks([rsaKey('wide', { x5t: 'a', x5u: 'https://x.example.invalid', key_ops: ['verify'] })]) }),
    { limits: { maxListEntries: 4 } },
  )
  assert.equal(findingsFor(wideKey, 'too-many-list-entries')[0].location.pointer, '/keys/0')
  assert.equal(wideKey.summary.keys, 0)
})

test('the findings limit is reported as itself and the report says it is partial', async () => {
  const many = []
  for (let index = 0; index < 12; index += 1) many.push(`https://app.example.invalid/cb-${index}`)
  const report = await apiReport(
    fixture({ client: client({ redirectUris: many }) }),
    { limits: { maxFindings: 5 } },
  )

  assert.equal(report.findings.length, 5)
  const last = findingsFor(report, 'too-many-findings')[0]
  assert.equal(last.message.includes('maxFindings limit of 5'), true)
  assert.equal(report.status, 'incomplete')
})

test('the time budget fires, and the phase it interrupted reports nothing rather than part', async () => {
  let now = 0
  const report = await apiReport(fixture({ jwks: jwks([rsaKey('a'), rsaKey('b'), rsaKey('c')]) }), {
    limits: { maxRuntimeMs: 5 },
    // Each reading advances the clock, so the budget is passed part way through
    // the run without any waiting at all.
    clock: () => {
      now += 3
      return now
    },
  })

  assert.equal(findingsFor(report, 'time-budget-exceeded')[0].message.includes('maxRuntimeMs budget of 5'), true)
  assert.equal(report.status, 'incomplete')
  assert.deepEqual(report.profile.signingKeys, [], 'an interrupted phase contributes nothing')
  assert.equal(report.summary.keys, 0)
})

test('a clock that never advances never fires the budget', async () => {
  const report = await apiReport(clean(), { limits: { maxRuntimeMs: 1 }, clock: () => 0 })

  assert.deepEqual(raisedRules(report), [])
  assert.equal(report.status, 'pass')
})

test('a clock that is not a function is a configuration error, not a default', async () => {
  await assert.rejects(() => checkOidcConfiguration({ root: '.', clock: 5 }), /clock must be a function/)
})
