import assert from 'node:assert/strict'
import test from 'node:test'

import { hasForbiddenCharacter } from '../src/index.mjs'
import {
  FORBIDDEN,
  apiReport,
  cliReport,
  cliRun,
  client,
  clean,
  findingsFor,
  fixture,
  jwks,
  metadata,
  policy,
  rsaKey,
  withRoot,
} from './support.mjs'

/**
 * Sanitisation, checked over the whole report rather than over one field.
 *
 * Four tools in this catalog stripped C0 and the line/paragraph separators and
 * let the C1 range through, and one of them sanitised its evidence carefully
 * and left its identifiers raw -- so a page id holding a newline forged whole
 * lines in the human report. Every case below walks the serialised report and
 * asserts that nothing survived anywhere, and two of them count the lines the
 * human report actually printed.
 */

/**
 * The human report separates its lines with U+000A, which is itself in the C0
 * class, so a whole stream cannot be checked as one string. Each printed line is
 * checked instead -- which is the stronger question anyway: the damage a control
 * character does here is to the line it lands in.
 */
const everyLineIsClean = (stream) => stream.split(String.fromCharCode(10)).every((line) => !hasForbiddenCharacter(line))

test('a forbidden character arriving through a key id is refused, and none of it reaches the report', async () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const report = await apiReport(fixture({ jwks: jwks([rsaKey(`2026${character}03-signing`)]) }))

    assert.equal(findingsFor(report, 'jwk-kid-invalid').length, 1, `${name} must be refused as a key id`)
    assert.equal(findingsFor(report, 'jwk-kid-invalid')[0].location.pointer, '/keys/0/kid')
    assert.equal(hasForbiddenCharacter(JSON.stringify(report)), false, `${name} must not survive anywhere in the report`)
    assert.equal(JSON.stringify(report).includes('2026'), false, `${name}: a refused value is described, not reproduced`)
  }
})

test('a forbidden character arriving through a client id is refused the same way', async () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const report = await apiReport(fixture({ client: client({ clientId: `storefront${character}web` }) }))

    assert.equal(findingsFor(report, 'client-invalid')[0].location.pointer, '/clientId', name)
    assert.equal(hasForbiddenCharacter(JSON.stringify(report)), false, name)
    assert.equal(JSON.stringify(report).includes('storefront'), false, name)
  }
})

test('a forbidden character arriving through an object key is echoed only after it is stripped', async () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const report = await apiReport(fixture({ metadata: metadata({ [`tenant${character}id`]: 'one' }) }))

    const finding = findingsFor(report, 'metadata-key-unknown')[0]
    assert.equal(finding.message.includes('does not recognise'), true, `${name} arrives through a key`)
    assert.equal(hasForbiddenCharacter(JSON.stringify(report)), false, `${name} must not survive anywhere in the report`)
    assert.equal(hasForbiddenCharacter(finding.location.pointer), false, `${name} reaches the pointer too`)
  }
})

test('a forbidden character arriving through a redirect URI refuses the URI outright', async () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const uri = `https://app.example.invalid/auth${character}callback`
    const report = await apiReport(fixture({
      client: client({ redirectUris: [uri] }),
      policy: policy({ allowedRedirectUris: [uri] }),
    }))

    const finding = findingsFor(report, 'redirect-uri-invalid')[0]
    assert.equal(finding.message.includes('control, separator or bidi character'), true, name)
    assert.equal(hasForbiddenCharacter(JSON.stringify(report)), false, name)
    assert.equal(JSON.stringify(report).includes('app.example.invalid/auth'), false, `${name}: never reproduced`)
  }
})

test('default-ignorable marks cannot create a passing invisible redirect or issuer identity', async () => {
  const plainRedirect = 'https://app.example.invalid/cb'
  const plainIssuer = 'https://id.example.invalid/tenant'
  const redirectControl = await cliReport(fixture({
    client: client({ redirectUris: [plainRedirect] }),
    policy: policy({ allowedRedirectUris: [plainRedirect] }),
  }))
  const issuerControl = await cliReport(fixture({
    metadata: metadata({ issuer: plainIssuer }),
    client: client({ expectedIssuer: plainIssuer }),
  }))
  assert.equal(redirectControl.code, 0)
  assert.equal(redirectControl.report.status, 'pass')
  assert.equal(issuerControl.code, 0)
  assert.equal(issuerControl.report.profile.issuerMatches, true)

  for (const point of [0x034f, 0x200b, 0xfe0f]) {
    const mark = String.fromCharCode(point)
    const redirect = `https://app.example.invalid/c${mark}b`
    const redirectRun = await cliReport(fixture({
      client: client({ redirectUris: [redirect] }),
      policy: policy({ allowedRedirectUris: [redirect] }),
    }))
    assert.equal(redirectRun.code, 2, `U+${point.toString(16)} redirect`)
    assert.equal(redirectRun.report.status, 'incomplete')
    assert.equal(findingsFor(redirectRun.report, 'redirect-uri-invalid').length, 2)
    assert.equal(redirectRun.stdout.includes(mark), false)

    const issuer = `https://id.example.invalid/te${mark}nant`
    const issuerRun = await cliReport(fixture({
      metadata: metadata({ issuer }),
      client: client({ expectedIssuer: issuer }),
    }))
    assert.equal(issuerRun.code, 2, `U+${point.toString(16)} issuer`)
    assert.equal(issuerRun.report.status, 'incomplete')
    assert.equal(issuerRun.report.profile.issuerMatches, null)
    assert.equal(issuerRun.stdout.includes(mark), false)

    for (const [provider, expected] of [[issuer, plainIssuer], [plainIssuer, issuer]]) {
      const oneSided = await cliReport(fixture({
        metadata: metadata({ issuer: provider }),
        client: client({ expectedIssuer: expected }),
      }))
      assert.equal(oneSided.code, 2, `U+${point.toString(16)} on one issuer side`)
      assert.equal(oneSided.report.profile.issuerMatches, null)
      assert.equal(oneSided.stdout.includes(mark), false)
    }
  }
})

test('default-ignorable marks in untrusted report labels are stripped before JSON output', async () => {
  const mark = String.fromCharCode(0x034f)
  const { code, stdout, report } = await cliReport(fixture({
    metadata: metadata({ [`tenant${mark}id`]: 'synthetic' }),
  }))
  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(findingsFor(report, 'metadata-key-unknown').length, 1)
  assert.equal(stdout.includes(mark), false)
  assert.equal(hasForbiddenCharacter(JSON.stringify(report)), false)
})

test('a line separator arriving through an identifier cannot forge a line in the human report', async () => {
  for (const character of [FORBIDDEN['C0 LF'], FORBIDDEN['C1 NEL'], FORBIDDEN['line separator'], FORBIDDEN['paragraph separator']]) {
    const files = fixture({
      metadata: metadata({ [`tenant${character}ERROR   forged.json fake-rule invented`]: 'one' }),
    })

    const result = await withRoot(files, (root) => cliRun(['--root', root]))

    assert.equal(result.code, 0, 'an unrecognised member is information, not a failure')
    const lines = result.stderr.split('\n')
    assert.equal(lines.at(-1), '', 'the report ends with a newline')
    assert.equal(lines.length, 6, 'four summary lines, one finding, and nothing forged')
    assert.equal(lines.filter((line) => line.startsWith('ERROR')).length, 0)
    assert.equal(everyLineIsClean(result.stderr), true)
  }
})

test('a bidi override cannot reverse what the human report prints', async () => {
  const files = fixture({
    client: client({ redirectUris: [`https://app.example.invalid/${FORBIDDEN['bidi RLO']}gnp.callback`] }),
  })
  const result = await withRoot(files, (root) => cliRun(['--root', root]))

  assert.equal(everyLineIsClean(result.stderr), true)
  assert.equal(result.stderr.includes(FORBIDDEN['bidi RLO']), false)
  assert.equal(result.code, 2)
})

test('an argument is flattened before it reaches a stream, because argv never passes through a finding', async () => {
  const result = await cliRun([`--unknown${FORBIDDEN['C0 LF']}option`, '--root', '.'])

  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.equal(everyLineIsClean(result.stderr), true)
  assert.equal(result.stderr.startsWith('Unknown option "--unknown option"'), true)
})

test('a file name carrying a forbidden character is refused as configuration, before any read', async () => {
  const result = await cliRun(['--root', '.', '--jwks', `jwks${FORBIDDEN['line separator']}.json`])

  assert.equal(result.code, 2)
  assert.equal(result.stdout, '', 'a configuration error never had a subject, so stdout stays empty')
  assert.equal(result.stderr.includes('must not contain a control, separator or bidi character'), true)
  assert.equal(everyLineIsClean(result.stderr), true)
})

test('nothing forbidden survives in a report that raises many different rules at once', async () => {
  const { report } = await cliReport({
    ...clean(),
    'metadata.json': metadata({
      issuer: `https://id.example.invalid${FORBIDDEN['C1 CSI']}`,
      [`vendor${FORBIDDEN.DEL}key`]: 1,
      id_token_signing_alg_values_supported: [`RS${FORBIDDEN['C0 ESC']}256`, 'none'],
    }),
    'jwks.json': jwks([rsaKey(`kid${FORBIDDEN['C0 NUL']}one`), rsaKey('two', { alg: `RS${FORBIDDEN['bidi isolate']}256` })]),
    'client.json': client({ redirectUris: [`https://app.example.invalid/${FORBIDDEN['bidi RLM']}cb`] }),
  })

  assert.equal(hasForbiddenCharacter(JSON.stringify(report)), false)
  assert.equal(report.findings.length > 4, true, 'several rules must fire for this case to mean anything')
  assert.equal(report.status, 'incomplete')
})
