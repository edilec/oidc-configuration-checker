import assert from 'node:assert/strict'
import { readdir } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import { cliRun, projectDirectory, raisedRules } from './support.mjs'

/**
 * The shipped examples, run as the README says to run them.
 *
 * `npm run example` is part of `npm run check`, so the clean example failing
 * would already break the build. These cases add the two that are supposed to
 * be broken -- an example whose output nobody asserts is an example that stops
 * matching the tool it documents.
 */

async function example(name, extraArgs = []) {
  const root = join(projectDirectory, 'examples', name)
  const result = await cliRun(['--root', root, '--json', ...extraArgs])
  return { ...result, report: result.stdout === '' ? null : JSON.parse(result.stdout) }
}

test('every example directory holds exactly the four documents', async () => {
  for (const name of ['broken', 'clean', 'incomplete']) {
    const entries = (await readdir(join(projectDirectory, 'examples', name))).sort()
    assert.deepEqual(entries, ['client.json', 'jwks.json', 'metadata.json', 'policy.json'])
  }
})

test('the clean example passes with nothing to report', async () => {
  const { code, report } = await example('clean')

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.deepEqual(report.findings, [])
  assert.equal(report.summary.checked, 15)
  assert.equal(report.summary.endpoints, 5)
  assert.equal(report.summary.keys, 3)
  assert.equal(report.summary.usableKeys, 3)
})

test('the clean example is ready for a rotation, with every key identified', async () => {
  const { report } = await example('clean')

  assert.equal(report.profile.issuerMatches, true)
  assert.deepEqual(
    report.profile.signingKeys,
    [
      { kid: '2025-09-signing', kty: 'RSA', alg: 'RS256', status: 'usable' },
      { kid: '2026-03-signing', kty: 'RSA', alg: 'RS256', status: 'usable' },
      { kid: '2026-03-signing-ec', kty: 'EC', alg: 'ES256', status: 'usable' },
    ],
  )
  assert.deepEqual(report.profile.redirectUris, [
    { uri: 'https://app.example.invalid/auth/callback', status: 'allowlisted' },
  ])
})

test('the broken example completes and fails, with a verdict rather than a gap', async () => {
  const { code, report } = await example('broken')

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.deepEqual(raisedRules(report), [
    'alg-none-offered',
    'issuer-mismatch',
    'jwk-kid-missing',
    'jwks-too-few-keys',
    'redirect-uri-not-allowlisted',
  ])
  assert.equal(report.summary.errors, 5)
  assert.equal(report.summary.warnings, 0)
})

test('the broken example carries each of the three acceptance failures at once', async () => {
  const { report } = await example('broken')

  assert.equal(report.profile.issuerMatches, false, 'issuer mismatch')
  assert.equal(report.profile.signingKeys.some((row) => row.kid === null), true, 'a key with no id')
  assert.equal(report.profile.algorithms.offered.includes('none'), true, 'an algorithm nothing may use')
  assert.equal(report.summary.usableKeys, 1, 'and one usable key is not a rotation')
})

test('the incomplete example is incomplete, and nothing unknown is assumed safe', async () => {
  const { code, report } = await example('incomplete')

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.deepEqual(raisedRules(report), [
    'jwk-alg-undeclared',
    'jwk-alg-unrecognised',
    'jwks-too-few-keys',
    'redirect-uri-wildcard',
  ])
  assert.equal(report.summary.keys, 3)
  assert.equal(report.summary.usableKeys, 1)
  assert.deepEqual(
    report.profile.signingKeys.map((row) => row.status),
    ['unknown', 'usable', 'unknown'],
  )
})

test('the incomplete example still reports what it did establish', async () => {
  const { report } = await example('incomplete')

  assert.equal(report.profile.issuerMatches, true)
  assert.deepEqual(report.profile.redirectUris, [
    { uri: 'https://app.example.invalid/auth/callback', status: 'allowlisted' },
  ])
})
