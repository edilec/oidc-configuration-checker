import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CALLBACK,
  SIGNED_OUT,
  apiReport,
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
import { formatReport, parseFailureDetail } from '../src/index.mjs'

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
 *
 * One path needed saying out loud, because every fixture that plants a canary
 * in a *field* is valid JSON by construction and therefore never reaches it:
 * the document that will not parse at all. That is the one place raw file bytes
 * are handled by something other than this package -- V8 writes them into its
 * own error message -- so the cases below drive canaries through it directly,
 * including the shape whose own text reads like a position.
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

test('a queryless accepted redirect URI keeps its exact display', async () => {
  // Worth stating plainly: a registered redirect URI is public configuration
  // and the report exists to tell you which ones are registered. Its queryless
  // spelling can appear in the profile. Query and fragment values are different:
  // exact comparison still reads them, but the report must not publish them.
  const { report } = await streamsFor(clean())

  assert.deepEqual(report.profile.redirectUris, [{ uri: CALLBACK, pointer: '/redirectUris/0', truncated: false, redacted: false, status: 'allowlisted' }])
})

test('accepted query-bearing URI values stay exact for matching but are redacted in profile and both streams', async () => {
  const canary = 'SYNTHETIC_SECRET_CANARY'
  const redirect = `${CALLBACK}?code=${canary}`
  const logout = `${SIGNED_OUT}?code=${canary}`
  const input = fixture({
    client: client({ redirectUris: [redirect], postLogoutRedirectUris: [logout] }),
    policy: policy({ allowedRedirectUris: [redirect], allowedPostLogoutRedirectUris: [logout] }),
  })
  const report = await apiReport(input)
  assert.equal(report.status, 'pass')
  assert.deepEqual(report.findings, [])
  assert.deepEqual(report.profile.redirectUris[0], {
    uri: `${CALLBACK}?[redacted-query]`, pointer: '/redirectUris/0', truncated: false, redacted: true, status: 'allowlisted',
  })
  assert.deepEqual(report.profile.postLogoutUris[0], {
    uri: `${SIGNED_OUT}?[redacted-query]`, pointer: '/postLogoutRedirectUris/0', truncated: false, redacted: true, status: 'allowlisted',
  })
  assert.equal(JSON.stringify(report).includes(canary), false)
  assert.equal(formatReport(report).includes(canary), false)
  await withRoot(input, async (root) => {
    const run = await cliRun(['--root', root])
    assert.equal(run.code, 0)
    assert.equal(run.stdout.includes(canary), false)
    assert.equal(run.stderr.includes(canary), false)
  })
})

test('query-bearing mismatch, spare allowlist entry, issuer and endpoint findings never publish query text', async () => {
  const canary = 'SYNTHETIC_SECRET_CANARY'
  const redirect = `${CALLBACK}?code=${canary}`
  const mismatch = await apiReport(fixture({ client: client({ redirectUris: [redirect] }) }))
  assert.equal(mismatch.status, 'fail')
  assert.equal(JSON.stringify(mismatch).includes(canary), false)
  assert.equal(findingsFor(mismatch, 'redirect-uri-not-allowlisted')[0].location.pointer, '/redirectUris/0')

  const unused = await apiReport(fixture({ policy: policy({ allowedRedirectUris: [CALLBACK, redirect] }) }))
  assert.equal(unused.status, 'pass')
  assert.equal(JSON.stringify(unused).includes(canary), false)
  assert.equal(findingsFor(unused, 'redirect-uri-unused')[0].location.pointer, '/allowedRedirectUris/1')

  const issuer = `https://id.example.invalid/issuer?code=${canary}`
  const provider = await apiReport(fixture({
    metadata: metadata({ issuer, authorization_endpoint: `http://id.example.invalid/authorize?code=${canary}` }),
    client: client({ expectedIssuer: issuer }),
  }))
  assert.equal(provider.status, 'fail')
  assert.equal(provider.profile.issuer, 'https://id.example.invalid/issuer?[redacted-query]')
  assert.equal(provider.profile.expectedIssuer, provider.profile.issuer)
  assert.equal(JSON.stringify(provider).includes(canary), false)
  assert.equal(formatReport(provider).includes(canary), false)
  assert.equal(findingsFor(provider, 'issuer-invalid').length > 0, true)
  assert.equal(findingsFor(provider, 'endpoint-not-https').length > 0, true)

  const differentIssuer = await apiReport(fixture({
    metadata: metadata({ issuer }),
    client: client({ expectedIssuer: 'https://id.example.invalid/issuer?code=OTHER' }),
  }))
  assert.equal(differentIssuer.status, 'fail')
  assert.equal(findingsFor(differentIssuer, 'issuer-mismatch')[0].evidence,
    'Exact issuer values differ beyond the displayed excerpt; provider /issuer; client /expectedIssuer')
  assert.equal(JSON.stringify(differentIssuer).includes(canary), false)
  assert.equal(formatReport(differentIssuer).includes(canary), false)
})

test('fragment text is marked as redacted even when the URI remains exactly allowlisted', async () => {
  const canary = 'SYNTHETIC_SECRET_CANARY'
  const uri = `${CALLBACK}#${canary}`
  const report = await apiReport(fixture({
    client: client({ redirectUris: [uri] }),
    policy: policy({ allowedRedirectUris: [uri] }),
  }))
  assert.equal(report.profile.redirectUris[0].status, 'allowlisted')
  assert.equal(report.profile.redirectUris[0].uri, `${CALLBACK}#[redacted-fragment]`)
  assert.equal(report.profile.redirectUris[0].redacted, true)
  assert.equal(JSON.stringify(report).includes(canary), false)
  assert.equal(formatReport(report).includes(canary), false)
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

test('a document that will not parse is reported by position, never quoted back', async () => {
  // V8 reports a parse failure two ways and one of them embeds the input:
  // `Unexpected token 'A', "AKIAIOSFODNN7EXAMPLE" is not valid JSON`. A client
  // document short enough to be only a secret is therefore reproduced in full
  // by its own error message -- on exactly the path a malformed or hostile
  // file takes -- and excerpting does not remove it: the quoted copy carries
  // no control characters and sits at the front of the message.
  const { report, scanned } = await streamsFor({ ...clean(), 'client.json': AWS_CANARY })

  const finding = findingsFor(report, 'input-not-json')[0]
  assert.equal(finding.location.file, 'client.json')
  assertNoTrace(scanned, AWS_CANARY, 'unparseable client document')
  assert.equal(finding.message, "client.json is not valid JSON: unexpected token 'A' at the start of the document")
  assert.equal(report.status, 'incomplete')
})

test('the same holds for the JSON report on stdout, and the position survives', async () => {
  const truncated = `{\n  "clientId": "${AWS_CANARY}",\n`
  const { code, stdout, stderr } = await withRoot(
    { ...clean(), 'client.json': truncated },
    (root) => cliRun(['--root', root, '--json']),
  )

  assert.equal(code, 2)
  assertNoTrace(`${stdout}${stderr}`, AWS_CANARY, 'truncated client document, --json')
  const finding = findingsFor(JSON.parse(stdout), 'input-not-json')[0]
  assert.match(finding.message, /at position \d+ \(line \d+ column \d+\)$/)
})

test('parseFailureDetail keeps the position and drops the quoted document', () => {
  const capture = (source) => {
    try {
      JSON.parse(source)
      return null
    } catch (error) {
      return error
    }
  }

  const quoting = capture(AWS_CANARY)
  assert.equal(quoting.message.includes(AWS_CANARY), true, 'V8 no longer quotes the input; this guard needs revisiting')
  assert.equal(parseFailureDetail(quoting), "unexpected token 'A' at the start of the document")

  // A longer document is quoted as a ten-character prefix rather than whole,
  // which a check for the entire value would miss entirely.
  const longCanary = `secret-${CARD_CANARY}`
  const truncatedSnippet = capture(longCanary)
  assert.equal(truncatedSnippet.message.includes(longCanary.slice(0, 10)), true, 'V8 no longer truncates at ten')
  assertNoTrace(parseFailureDetail(truncatedSnippet), longCanary, 'ten-character snippet')

  assert.match(parseFailureDetail(capture('{"a": 1, ')), /at position \d+ \(line \d+ column \d+\)$/)
  assert.equal(parseFailureDetail(capture('')), 'Unexpected end of JSON input')
  assert.equal(parseFailureDetail(new Error('unrecognised shape')), 'the document could not be parsed as JSON')
})

/**
 * The trap the first version of this guard walked into: a document whose own
 * text reads `at position 1`.
 *
 * V8 answers it with `Unexpected token 'a', "at position 1" is not valid JSON`,
 * which carries both spellings at once -- the quoted copy of the document, and,
 * inside that copy, something that reads exactly like an offset. The guard
 * looked for the offset first, found the document's own text, sliced the
 * message there and shipped the quoted span it exists to remove. Measured
 * before the fix, a `policy.json` holding `AKIAIOSat position 1` put the
 * seven-character prefix `AKIAIOS` on both streams -- above the six-character
 * standard this file holds the tool to. The offset is only safe once the
 * quoting shape has been ruled out, so the quoting shape is recognised first.
 */
test('a document whose own text reads "at position 1" is not sliced back out of the message', async () => {
  const capture = (source) => {
    try {
      JSON.parse(source)
      return null
    } catch (error) {
      return error
    }
  }

  // Seven characters of the canary is what fits in front of `at position 1`
  // inside V8's twenty-character quoting window.
  const leading = AWS_CANARY.slice(0, 7)
  const planted = capture(`${leading}at position 1`)
  assert.equal(planted.message.includes(leading), true, 'V8 still quotes the canary, so this test still has a subject')
  assertNoTrace(parseFailureDetail(planted), leading, 'a document reading like an offset')
  assert.equal(parseFailureDetail(planted), "unexpected token 'A' at the start of the document")

  // Exactly twenty characters, which is where V8 stops quoting the whole
  // document and starts quoting a window, so this span holds both a line break
  // and the offset text. Without the `s` flag the quoting shape does not match
  // across the break, the offset inside the span matches instead, and the
  // document comes back out.
  const wrapped = capture(`${AWS_CANARY.slice(0, 6)}\nat position 1`)
  assert.equal(wrapped.message.includes('\n'), true, 'the quoted span still carries the newline')
  assertNoTrace(parseFailureDetail(wrapped), AWS_CANARY.slice(0, 6), 'a quoted span carrying a newline')
  assert.equal(parseFailureDetail(wrapped), "unexpected token 'A' at the start of the document")

  // A failure reached from inside the document says so rather than claiming
  // the start, and a long document with a sensitive prefix keeps nothing of it.
  const inside = parseFailureDetail(capture(`{"issuer": "https://id.example.invalid", "x": ${AWS_CANARY}}`))
  assertNoTrace(inside, AWS_CANARY, 'a failure inside the document')
  assert.equal(inside, "unexpected token 'A' inside the document")

  const long = parseFailureDetail(capture(`${AWS_CANARY}${'-'.repeat(4000)}`))
  assertNoTrace(long, AWS_CANARY, 'a long document with a sensitive prefix')
  assert.equal(long, "unexpected token 'A' at the start of the document")

  // The safe positional spelling is still reported in full, up to the offset.
  assert.equal(
    parseFailureDetail(capture('{"issuer": "https://id.example.invalid" "x": 1}')),
    "Expected ',' or '}' after property value in JSON at position 40 (line 1 column 41)",
  )
})

test('a quoting wording this build has never seen is refused wholesale', () => {
  // The closing guard, and the only thing between a future V8 wording and the
  // document it failed on. This message quotes the input and matches no branch;
  // the offset inside the quoted span is the only thing that does, so without
  // the guard the span ships.
  const unseen = { message: `Unexpected token 'A', "${AWS_CANARY} at position 5" is not valid JSON.` }
  const detail = parseFailureDetail(unseen)

  assertNoTrace(detail, AWS_CANARY, 'an unrecognised wording')
  assert.equal(detail, 'the document could not be parsed as JSON')
})
