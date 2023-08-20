import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import {
  cliReport,
  client,
  ecKey,
  findingsFor,
  fixture,
  jwks,
  metadata,
  policy,
  projectDirectory,
  rsaKey,
} from './support.mjs'

/**
 * The acceptance evidence this tool was built to produce, asserted through the
 * real binary in the words the requirement used.
 *
 *   "Issuer mismatch, missing key IDs and unsupported algorithms fail; token
 *    acquisition and login bypass are outside scope."
 *
 * The first half is three behaviours and they are pinned here by exit code. The
 * second half is a promise about what the package does *not* contain, and the
 * last two cases are what that promise is worth: a scan of everything that
 * ships, and a statement in the documentation that a reader can check.
 */

test('an issuer mismatch fails', async () => {
  const { code, report } = await cliReport(fixture({ metadata: metadata({ issuer: 'https://login.example.invalid' }) }))

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(findingsFor(report, 'issuer-mismatch').length, 1)
  assert.equal(report.profile.issuerMatches, false)
})

test('a missing key id fails', async () => {
  const { code, report } = await cliReport(fixture({ jwks: jwks([rsaKey('2026-03-signing'), rsaKey(undefined)]) }))

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(findingsFor(report, 'jwk-kid-missing').length, 1)
  assert.equal(report.summary.usableKeys, 1, 'a key a rotation cannot select is not a key a rotation can use')
})

test('an algorithm the policy does not permit fails, on the client and on a key', async () => {
  const setting = await cliReport(fixture({
    client: client({ idTokenSignedResponseAlg: 'ES256' }),
    metadata: metadata({ id_token_signing_alg_values_supported: ['ES256', 'RS256'] }),
  }))
  assert.equal(setting.code, 1)
  assert.equal(setting.report.status, 'fail')
  assert.equal(findingsFor(setting.report, 'alg-not-permitted').length, 1)

  const key = await cliReport(fixture({ jwks: jwks([rsaKey('rsa'), ecKey('ec')]) }))
  assert.equal(key.code, 1)
  assert.equal(key.report.status, 'fail')
  assert.equal(findingsFor(key.report, 'jwk-alg-not-permitted').length, 1)
})

test('an algorithm nobody here implements does not pass either, and is not called refused', async () => {
  const { code, report } = await cliReport(fixture({ jwks: jwks([rsaKey('modern', { alg: 'BS256' })]) }))

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(findingsFor(report, 'jwk-alg-unrecognised').length, 1)
  assert.equal(report.profile.signingKeys[0].status, 'unknown')
  assert.equal(report.summary.usableKeys, 0, 'unsupported is not approved')
})

test('"none" fails wherever it appears, including in the policy that permits it', async () => {
  const offered = await cliReport(fixture({ metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'none'] }) }))
  assert.equal(offered.code, 1)

  const selected = await cliReport(fixture({ client: client({ idTokenSignedResponseAlg: 'none' }) }))
  assert.equal(selected.code, 1)

  const permitted = await cliReport(fixture({ policy: policy({ allowedIdTokenSigningAlgs: ['RS256', 'none'] }) }))
  assert.equal(permitted.code, 1)
})

test('a redirect allowlist is matched exactly, and a wildcard is refused rather than expanded', async () => {
  const exact = await cliReport(fixture({ client: client({ redirectUris: ['https://app.example.invalid/auth/callback/'] }) }))
  assert.equal(exact.code, 1)
  assert.equal(findingsFor(exact.report, 'redirect-uri-not-allowlisted').length, 1)

  const wildcard = await cliReport(fixture({
    policy: policy({ allowedRedirectUris: ['https://app.example.invalid/auth/*'] }),
  }))
  assert.equal(wildcard.code, 2)
  assert.equal(findingsFor(wildcard.report, 'redirect-uri-wildcard').length, 1)
})

/**
 * "Token acquisition and login bypass are outside scope."
 *
 * The scan below is deliberately crude and deliberately wide: it looks for the
 * vocabulary a tool would need in order to do any of it. A tool that requested
 * a token would name a grant type in a request body; one that verified a
 * signature would import a verifier; one that bypassed a login would need
 * somewhere to send the result. None of that is here, and the point of scanning
 * for the words is that adding any of it later fails this test.
 */
test('nothing that ships could acquire a token, verify one, or perform any part of a flow', async () => {
  const parts = []
  for (const directory of ['bin', 'src']) {
    for (const name of (await readdir(join(projectDirectory, directory))).sort()) {
      parts.push(await readFile(join(projectDirectory, directory, name), 'utf8'))
    }
  }
  const source = parts.join('\n')

  assert.deepEqual(
    source.split('\n').filter((line) => line.includes('node:crypto')),
    [],
    'the report does not publish a cryptographic identity label for a URI',
  )

  for (const verb of [
    'createVerify', 'createHmac', 'importKey', 'crypto.subtle', 'jwtVerify', 'decodeJwt',
    'grant_type=', 'client_assertion', 'code_verifier', 'access_token=', 'refresh_token=',
    'Authorization:', 'Bearer ', 'set-cookie', 'Set-Cookie',
  ]) {
    assert.equal(source.includes(verb), false, `the source mentions ${verb}`)
  }

  // The discovery vocabulary the tool *reads* is a different thing from the
  // vocabulary it would need in order to act: "grant_types_supported" is a
  // member name in a document, and it is the only word above that comes close.
  assert.equal(source.includes('grant_types_supported'), true, 'the metadata member is read')
})

test('the documentation says plainly what the tool does not do', async () => {
  const readme = await readFile(join(projectDirectory, 'README.md'), 'utf8')
  const rules = await readFile(join(projectDirectory, 'docs/oidc-rules.md'), 'utf8')

  // The claims themselves, not the words they happen to contain. Asking only
  // that the README mention "never", "token" and "flow" somewhere in its
  // lowercase form is satisfied by almost any prose about an OIDC tool -- the
  // sentence describing the JSON envelope carries all three -- so a README that
  // had dropped its non-goals entirely would still have passed.
  // Line wrapping is not the subject, so the prose is compared with its
  // whitespace flattened; the claim is.
  const prose = readme.replace(/\s+/g, ' ')
  for (const claim of [
    'It performs no part of an OpenID Connect flow.',
    'It does not fetch the discovery document or the key set',
    'obtain, decode or verify a token',
    'Token acquisition and login bypass are outside its scope',
    'no credential is read from any source',
    'Nothing was fetched.',
  ]) {
    assert.equal(prose.includes(claim), true, `README.md no longer says: ${claim}`)
  }
  assert.equal(readme.includes('Limits and non-goals'), true)
  assert.equal(rules.includes('What this tool does not do'), true)
})
