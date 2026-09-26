import assert from 'node:assert/strict'
import test from 'node:test'

import {
  EC_P256,
  OKP_ED25519,
  RSA_1024,
  RSA_2048_NEXT,
  apiReport,
  client,
  ecKey,
  findingsFor,
  fixture,
  jwks,
  keyRow,
  metadata,
  policy,
  raisedRules,
  rsaKey,
} from './support.mjs'

/**
 * The key set: identity, algorithm and rotation readiness.
 *
 * Three ideas run through every case below.
 *
 * - A key with no `kid` is a key a rotation cannot select. That is a verdict,
 *   not a gap: the absence is known, so the run fails rather than going
 *   incomplete.
 * - A key whose algorithm or key type this build does not implement is
 *   **unsupported**. It is not counted as usable and the run is incomplete --
 *   unsupported is not approved.
 * - Nothing here reads, decodes or reports private material. A key set is
 *   published; a private parameter in one is the finding, and its value never
 *   reaches the report.
 */

const withKeys = (keys, overrides = {}) => fixture({ jwks: jwks(keys), ...overrides })

test('a key set with two usable keys is ready for a rotation', async () => {
  const report = await apiReport(withKeys(
    [rsaKey('2026-03-signing'), rsaKey('2025-09-signing', { n: RSA_2048_NEXT.n })],
    { policy: policy({ minimumKeys: 2 }) },
  ))

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.keys, 2)
  assert.equal(report.summary.usableKeys, 2)
  assert.equal(keyRow(report, '2026-03-signing').status, 'usable')
})

test('a key with no kid fails, and is not counted as usable', async () => {
  const report = await apiReport(withKeys([rsaKey('2026-03-signing'), rsaKey(undefined)]))

  const finding = findingsFor(report, 'jwk-kid-missing')[0]
  assert.equal(finding.location.pointer, '/keys/1')
  assert.equal(finding.message.includes('rotation cannot be staged'), true)
  assert.equal(report.status, 'fail', 'the absence is known, so this is a verdict')
  assert.equal(report.summary.usableKeys, 1)
})

test('a kid that is not a usable identifier is refused without being reproduced', async () => {
  const report = await apiReport(withKeys([rsaKey(17)]))

  assert.equal(findingsFor(report, 'jwk-kid-invalid')[0].location.pointer, '/keys/0/kid')
  assert.equal(JSON.stringify(report).includes('17'), false)
  assert.equal(report.summary.usableKeys, 0)
})

test('two keys answering to one kid make the rotation undefined', async () => {
  const report = await apiReport(withKeys([rsaKey('shared'), rsaKey('shared', { n: RSA_2048_NEXT.n })]))

  const finding = findingsFor(report, 'jwk-kid-duplicate')[0]
  assert.equal(finding.location.pointer, '/keys/1/kid')
  assert.equal(finding.message.includes('/keys/0/kid'), true)
  assert.equal(report.summary.usableKeys, 1)
  assert.equal(report.status, 'fail')
})

/**
 * What "refused" means in a key row, now that nothing counts it separately.
 *
 * `checkKeys` used to return a `refused` tally that `runChecks` never read, and
 * the tally was not even right: a key refused for a duplicate `kid` is marked
 * after `checkKey` has returned, so it never reached the counter. The rows are
 * the record -- a refused key is reported, carries `status: "refused"`, and is
 * outside the usable set -- and that is what this case pins, for both routes
 * into the status.
 */
test('every refused key is reported, carries the status, and is outside the usable set', async () => {
  const report = await apiReport(withKeys([
    rsaKey('rotating'),
    rsaKey('unsigned', { alg: 'none', n: RSA_2048_NEXT.n }),
    rsaKey('rotating', { n: RSA_1024.n, e: RSA_1024.e }),
  ]))

  assert.equal(keyRow(report, 'unsigned').status, 'refused', 'refused inside checkKey')
  assert.equal(report.profile.signingKeys.filter((row) => row.status === 'refused').length, 2, 'and refused after it, for the duplicate kid')
  assert.equal(report.summary.keys, 3)
  assert.equal(report.summary.usableKeys, 1)
  assert.equal(
    report.profile.signingKeys.filter((row) => row.status === 'usable').length,
    report.summary.usableKeys,
    'the usable count is the rows, not a tally kept beside them',
  )
  assert.equal(report.status, 'fail')
})

test('one usable key against a policy that requires two is a rotation nobody can stage', async () => {
  const report = await apiReport(withKeys([rsaKey('only')], { policy: policy({ minimumKeys: 2 }) }))

  assert.deepEqual(raisedRules(report), ['jwks-too-few-keys'])
  assert.equal(findingsFor(report, 'jwks-too-few-keys')[0].message.includes('outage or a gap'), true)
  assert.equal(report.status, 'fail')
})

test('a key set with nothing usable in it says so once', async () => {
  const report = await apiReport(withKeys([rsaKey(undefined)], { policy: policy({ minimumKeys: 2 }) }))

  assert.equal(findingsFor(report, 'jwks-no-signing-key').length, 1)
  assert.equal(findingsFor(report, 'jwks-too-few-keys').length, 0, 'the two rules never both fire')
})

test('an empty key set is a failure, not an absence of evidence', async () => {
  const report = await apiReport(withKeys([]))

  assert.deepEqual(raisedRules(report), ['jwks-no-signing-key', 'jwks-selected-alg-unusable'])
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.keys, 0)
})

test('an algorithm this build does not implement is unsupported, not approved', async () => {
  const report = await apiReport(withKeys([rsaKey('modern', { alg: 'BS256' })]))

  const finding = findingsFor(report, 'jwk-alg-unrecognised')[0]
  assert.equal(finding.location.pointer, '/keys/0/alg')
  assert.equal(finding.message.includes('not the same as approved'), true)
  assert.equal(keyRow(report, 'modern').status, 'unknown')
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.usableKeys, 0)
})

test('a key that declares no algorithm is unknown, not permitted', async () => {
  const key = rsaKey('unlabelled')
  delete key.alg
  const report = await apiReport(withKeys([key]))

  assert.equal(findingsFor(report, 'jwk-alg-undeclared').length, 1)
  assert.equal(keyRow(report, 'unlabelled').status, 'unknown')
  assert.equal(report.status, 'incomplete')
})

test('a key declaring alg none is refused outright', async () => {
  const report = await apiReport(withKeys([rsaKey('unsigned', { alg: 'none' })]))

  assert.equal(findingsFor(report, 'jwk-alg-none').length, 1)
  assert.equal(keyRow(report, 'unsigned').status, 'refused')
  assert.equal(report.status, 'fail', 'none is decided, never unknown')
})

test('a key type this build cannot inspect is unsupported', async () => {
  const report = await apiReport(withKeys([{ kty: 'Kyber768', kid: 'pq', alg: 'RS256' }]))

  assert.equal(findingsFor(report, 'jwk-kty-unsupported').length, 1)
  assert.equal(keyRow(report, 'pq').status, 'unknown')
  assert.equal(report.status, 'incomplete')
})

test('an algorithm the policy does not permit leaves the key out of the usable set', async () => {
  const report = await apiReport(withKeys(
    [rsaKey('permitted'), ecKey('spare')],
    { policy: policy({ allowedIdTokenSigningAlgs: ['RS256'] }) },
  ))

  assert.equal(findingsFor(report, 'jwk-alg-not-permitted')[0].location.pointer, '/keys/1/alg')
  assert.equal(keyRow(report, 'spare').status, 'not-permitted')
  assert.equal(report.summary.usableKeys, 1)
  assert.equal(report.status, 'fail')
})

test('an algorithm and a key type that cannot work together are reported as the pair they are', async () => {
  const report = await apiReport(withKeys([ecKey('mislabelled', { alg: 'RS256' })]))

  assert.equal(findingsFor(report, 'jwk-alg-key-mismatch').length, 1)
  assert.equal(report.status, 'fail')
})

test('a curve that does not carry its algorithm is a key nothing can verify with', async () => {
  const report = await apiReport(withKeys([ecKey('wrong-curve', { crv: 'P-384' })], {
    policy: policy({ allowedIdTokenSigningAlgs: ['ES256', 'RS256'] }),
  }))

  const finding = findingsFor(report, 'jwk-curve-mismatch')[0]
  assert.equal(finding.location.pointer, '/keys/0/crv')
  assert.equal(finding.message.includes('P-256'), true)
})

test('a coordinate of the wrong size for its curve is caught by measurement, not by trust', async () => {
  const report = await apiReport(withKeys([ecKey('short', { x: EC_P256.x.slice(0, 20) })], {
    policy: policy({ allowedIdTokenSigningAlgs: ['ES256'] }),
  }))

  const finding = findingsFor(report, 'jwk-invalid').find((entry) => entry.location.pointer === '/keys/0/x')
  assert.equal(finding.message.includes('and curve "P-256" uses 32'), true)
})

test('an RSA modulus below the policy floor is measured, not assumed', async () => {
  const report = await apiReport(withKeys([rsaKey('short', { n: RSA_1024.n, e: RSA_1024.e })]))

  const finding = findingsFor(report, 'jwk-rsa-modulus-short')[0]
  assert.equal(finding.message.includes('1024-bit modulus'), true)
  assert.equal(finding.message.includes('at least 2048'), true)
  assert.equal(report.status, 'fail')
})

test('a short modulus padded with leading zero bytes is still measured short', async () => {
  const padded = Buffer.concat([Buffer.alloc(128), Buffer.from(RSA_1024.n, 'base64url')]).toString('base64url')
  const report = await apiReport(withKeys([rsaKey('padded', { n: padded, e: RSA_1024.e })]))

  assert.equal(findingsFor(report, 'jwk-rsa-modulus-short')[0].message.includes('1024-bit modulus'), true)
})

test('an Ed25519 key is usable when the policy permits EdDSA', async () => {
  const report = await apiReport(withKeys(
    [{ kty: 'OKP', kid: 'ed', alg: 'EdDSA', crv: OKP_ED25519.crv, x: OKP_ED25519.x, use: 'sig' }],
    {
      client: client({ idTokenSignedResponseAlg: 'EdDSA' }),
      metadata: metadata({ id_token_signing_alg_values_supported: ['EdDSA'] }),
      policy: policy({ allowedIdTokenSigningAlgs: ['EdDSA'] }),
    },
  ))

  assert.deepEqual(raisedRules(report), [])
  assert.equal(keyRow(report, 'ed').status, 'usable')
})

test('a key marked for encryption is not a signing key and is not a finding', async () => {
  const report = await apiReport(withKeys([rsaKey('signing'), rsaKey('encrypting', { use: 'enc', n: RSA_2048_NEXT.n })]))

  assert.equal(keyRow(report, 'encrypting').status, 'encryption')
  assert.equal(report.summary.usableKeys, 1)
  assert.equal(report.status, 'pass')
})

test('a use this build does not know is refused', async () => {
  const report = await apiReport(withKeys([rsaKey('odd', { use: 'signing' })]))

  assert.equal(findingsFor(report, 'jwk-invalid')[0].location.pointer, '/keys/0/use')
  assert.equal(report.status, 'fail')
})

test('a key parameter that is absent or not base64url is named, and its value is not', async () => {
  const missing = rsaKey('no-modulus')
  delete missing.n
  const absent = await apiReport(withKeys([missing]))
  assert.equal(findingsFor(absent, 'jwk-invalid')[0].message.includes('"n" is absent'), true)

  const bad = await apiReport(withKeys([rsaKey('bad-modulus', { n: 'not base64url!!' })]))
  assert.equal(findingsFor(bad, 'jwk-invalid')[0].message.includes('is not base64url'), true)
  assert.equal(JSON.stringify(bad).includes('not base64url!!'), false)
})

test('the client accepting an algorithm no usable key carries is a verification that always fails', async () => {
  const report = await apiReport(withKeys([ecKey('ec-only')], {
    metadata: metadata({ id_token_signing_alg_values_supported: ['ES256', 'RS256'] }),
    policy: policy({ allowedIdTokenSigningAlgs: ['ES256', 'RS256'] }),
  }))

  assert.deepEqual(raisedRules(report), ['jwks-selected-alg-unusable'])
  assert.equal(report.status, 'fail')
})

test('a member this build does not recognise is reported and the key is still read', async () => {
  const report = await apiReport(withKeys([rsaKey('extended', { key_id: 'legacy' })]))

  const finding = findingsFor(report, 'jwk-member-unknown')[0]
  assert.equal(finding.severity, 'info')
  assert.equal(finding.location.pointer, '/keys/0/key_id')
  assert.equal(keyRow(report, 'extended').status, 'usable')
  assert.equal(report.status, 'pass')
})

test('the key set is sorted by kid, and a key with no kid still has a row', async () => {
  const report = await apiReport(withKeys([rsaKey('b-key'), rsaKey(undefined), rsaKey('a-key', { n: RSA_2048_NEXT.n })]))

  assert.deepEqual(report.profile.signingKeys.map((row) => row.kid), [null, 'a-key', 'b-key'])
})
