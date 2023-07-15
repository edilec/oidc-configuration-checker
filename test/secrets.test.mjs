import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CALLBACK,
  clean,
  client,
  cliRun,
  findingsFor,
  fixture,
  jwks,
  metadata,
  policy,
  rsaKey,
  withRoot,
} from './support.mjs'

/**
 * Nothing that looks like a credential reaches either stream.
 *
 * These files sit next to the files that hold client secrets, and a report is
 * piped, logged, archived by CI and pasted into issues. So the canaries below
 * are planted in every field a credential realistically arrives through -- a
 * private JWK parameter, a symmetric key, a `clientSecret` somebody added to
 * the client document, a vendor member of the discovery document, an
 * over-length value -- and the whole serialised report *and both streams* are
 * scanned for every prefix of each one. A redaction test that checks the field
 * somebody remembered is a test the next field passes for free.
 *
 * The canaries are published placeholders. `AKIAIOSFODNN7EXAMPLE` is the access
 * key id AWS documents, `4111111111111111` is the standard test card, and
 * `example.invalid` is reserved by RFC 2606. No fixture in this package carries
 * a real credential or a real private key.
 */

const AWS_CANARY = 'AKIAIOSFODNN7EXAMPLE'
const CARD_CANARY = '4111111111111111'
const MINIMUM_PREFIX = 6

/** Assert that no prefix of `canary` of 6 characters or more survives anywhere. */
function assertNoTrace(streams, canary, label) {
  for (let length = MINIMUM_PREFIX; length <= canary.length; length += 1) {
    assert.equal(
      streams.includes(canary.slice(0, length)),
      false,
      `${label}: a ${length}-character prefix reached a stream`,
    )
  }
}

/**
 * Run the real binary with the human report switched **on**, and return both
 * streams as one string to scan.
 *
 * Deliberately not `--json`: the human report on stderr prints messages,
 * evidence and summary lines that the JSON report also carries, and a redaction
 * test that only ever looked at stdout would pass on a leak that reached the
 * other stream.
 */
async function streamsFor(files) {
  const result = await withRoot(files, async (root) => {
    const run = await cliRun(['--root', root])
    return { ...run, report: run.stdout === '' ? null : JSON.parse(run.stdout) }
  })
  return { ...result, scanned: `${result.stdout}${result.stderr}` }
}

test('a private key parameter is named, never read, never measured and never echoed', async () => {
  const { report, scanned } = await streamsFor(fixture({
    jwks: jwks([rsaKey('leaked', { d: AWS_CANARY, p: AWS_CANARY, q: AWS_CANARY })]),
  }))

  const finding = findingsFor(report, 'jwk-private-material')[0]
  assert.equal(finding.message.includes('"d", "p", "q"'), true, 'the parameters are named')
  assert.equal(finding.message.includes('not reported'), true)
  assertNoTrace(scanned, AWS_CANARY, 'private RSA parameters')
  assert.equal(scanned.includes(String(AWS_CANARY.length)), false, 'not even the length')
  assert.equal(report.summary.usableKeys, 0)
})

test('a symmetric key in a published set is the finding, and its value stays in the file', async () => {
  const { report, scanned } = await streamsFor(fixture({
    jwks: jwks([{ kty: 'oct', kid: 'shared', alg: 'HS256', k: AWS_CANARY }]),
  }))

  assert.equal(findingsFor(report, 'jwk-private-material')[0].message.includes('"k"'), true)
  assertNoTrace(scanned, AWS_CANARY, 'symmetric key')
})

test('a key set that carries no k at all is still a published symmetric key', async () => {
  const { report } = await streamsFor(fixture({ jwks: jwks([{ kty: 'oct', kid: 'shared', alg: 'HS256' }]) }))

  const finding = findingsFor(report, 'jwk-private-material')[0]
  assert.equal(finding.message.includes('no public half'), true)
  assert.equal(report.status, 'fail')
})

test('a clientSecret added to the client document is refused, and its value never echoed', async () => {
  const { report, scanned } = await streamsFor(fixture({
    client: { ...client(), clientSecret: AWS_CANARY },
  }))

  const finding = findingsFor(report, 'client-invalid')[0]
  assert.equal(finding.message.includes('"clientSecret"'), true, 'the key is named')
  assertNoTrace(scanned, AWS_CANARY, 'clientSecret')
  assert.equal(report.status, 'incomplete')
})

test('a credential-shaped member of the discovery document is named, not read', async () => {
  const { report, scanned } = await streamsFor(fixture({
    metadata: metadata({ client_secret: AWS_CANARY, registration_access_token: AWS_CANARY }),
  }))

  assert.equal(findingsFor(report, 'metadata-key-unknown').length, 2)
  assertNoTrace(scanned, AWS_CANARY, 'discovery member')
})

test('an over-length value is described by its length alone, whatever it holds', async () => {
  const long = `https://app.example.invalid/cb?card=${CARD_CANARY}&pad=${'p'.repeat(2100)}`
  const { report, scanned } = await streamsFor(fixture({
    client: client({ redirectUris: [long] }),
    policy: policy({ allowedRedirectUris: [long] }),
  }))

  assert.equal(findingsFor(report, 'redirect-uri-invalid')[0].message.includes('longer than this build reads'), true)
  assertNoTrace(scanned, CARD_CANARY, 'over-length redirect URI')
})

test('an over-length description is refused without a word of it reaching the report', async () => {
  const { report, scanned } = await streamsFor(fixture({
    policy: policy({ description: `${CARD_CANARY} ${'d'.repeat(400)}` }),
  }))

  assert.equal(findingsFor(report, 'policy-invalid')[0].location.pointer, '/description')
  assertNoTrace(scanned, CARD_CANARY, 'policy description')
})

test('a redirect URI that is accepted is echoed on purpose, and that is the only kind that is', async () => {
  // Worth stating plainly: a registered redirect URI is public configuration
  // and the report exists to tell you which ones are registered, so an accepted
  // URI appears in the profile and in the evidence. Nothing that was *refused*
  // ever does -- which is what every other case in this file pins.
  const { report } = await streamsFor(clean())

  assert.deepEqual(report.profile.redirectUris, [{ uri: CALLBACK, status: 'allowlisted' }])
})

test('no fixture in the shipped examples carries a private key parameter', async () => {
  const { readFile, readdir } = await import('node:fs/promises')
  const { join } = await import('node:path')
  const { projectDirectory } = await import('./support.mjs')

  for (const directory of await readdir(join(projectDirectory, 'examples'))) {
    const text = await readFile(join(projectDirectory, 'examples', directory, 'jwks.json'), 'utf8')
    const parsed = JSON.parse(text)
    for (const key of parsed.keys) {
      for (const parameter of ['d', 'dp', 'dq', 'k', 'oth', 'p', 'q', 'qi']) {
        assert.equal(Object.hasOwn(key, parameter), false, `${directory}/jwks.json carries "${parameter}"`)
      }
    }
  }
})
