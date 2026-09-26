import assert from 'node:assert/strict'
import test from 'node:test'

import { RULE_SEVERITY, createFinding } from '../src/index.mjs'
import {
  apiReport,
  clean,
  client,
  fixture,
  jwks,
  metadata,
  policy,
  rsaKey,
} from './support.mjs'

/**
 * The report envelope and the finding shape, over a corpus wide enough that
 * most rules in the catalog actually fire.
 *
 * Every assertion here is about what a consumer can rely on: the fields that
 * are always present, the values `severity` may take, the fact that
 * `location.file` is the name the caller gave rather than a host path, and that
 * two runs over the same bytes produce the same bytes.
 */

const SEVERITIES = ['error', 'info', 'warning']

const CORPUS = Object.freeze([
  () => apiReport(clean()),
  () => apiReport(fixture({ metadata: metadata({ issuer: 'https://login.example.invalid', tenant: 'x' }) })),
  () => apiReport(fixture({ client: client({ redirectUris: ['https://app.example.invalid/other#f'] }) })),
  () => apiReport(fixture({ policy: policy({ redirectUriMatching: 'prefix', allowedRedirectUris: ['https://app.example.invalid/*'] }) })),
  () => apiReport(fixture({ jwks: jwks([rsaKey(undefined), rsaKey('x', { alg: 'BS256' }), { kty: 'oct', kid: 'shared', alg: 'HS256', k: 'AQAB' }]) })),
  () => apiReport(fixture({ metadata: metadata({ id_token_signing_alg_values_supported: ['none', 'ES256'] }) })),
  () => apiReport({ ...clean(), 'policy.json': 'not json' }),
  () => apiReport(fixture({ client: { schemaVersion: '1' } })),
])

async function everyFinding() {
  const findings = []
  for (const build of CORPUS) findings.push(...(await build()).findings)
  return findings
}

test('the corpus exercises a real spread of the catalog', async () => {
  const findings = await everyFinding()
  const rules = new Set(findings.map((finding) => finding.ruleId))

  assert.equal(rules.size > 15, true, `only ${rules.size} rules fired`)
  for (const ruleId of rules) assert.equal(Object.hasOwn(RULE_SEVERITY, ruleId), true, ruleId)
})

test('every finding carries the fields the report contract requires, and nothing unbounded', async () => {
  for (const finding of await everyFinding()) {
    assert.equal(typeof finding.ruleId, 'string')
    assert.equal(SEVERITIES.includes(finding.severity), true, finding.ruleId)
    // Deliberately *not* `finding.severity === RULE_SEVERITY[finding.ruleId]`:
    // `createFinding` assigns the severity straight out of that table, so the
    // comparison holds by construction for every finding the tool can emit and
    // cannot fail. What severity actually decides -- the summary counts, the
    // printed word and the exit code -- is pinned below and in
    // `test/severity-exit.test.mjs` and `test/severity-word.test.mjs`.
    assert.equal(typeof finding.message, 'string')
    assert.equal(finding.message.length > 0 && finding.message.length <= 403, true, finding.ruleId)
    assert.equal(typeof finding.location.file, 'string')
    assert.equal(typeof finding.location.pointer, 'string')
    assert.match(finding.location.file, /^[a-z]+\.json$/)
    assert.equal(finding.location.file.startsWith('/'), false, 'never a host path')
    if (finding.location.pointer !== '') assert.match(finding.location.pointer, /^\/[^ ]*$/, finding.location.pointer)
    if (finding.evidence !== undefined) assert.equal(finding.evidence.length <= 163, true)
    if (finding.suggestion !== undefined) assert.equal(finding.suggestion.length <= 303, true)
  }
})

test('the envelope is the one the report contract describes', async () => {
  const report = await apiReport(clean())

  assert.deepEqual(Object.keys(report), ['schemaVersion', 'tool', 'status', 'summary', 'profile', 'findings'])
  assert.equal(report.schemaVersion, '1')
  assert.equal(report.tool, 'oidc-configuration-checker')
  assert.deepEqual(
    Object.keys(report.summary),
    ['checked', 'errors', 'warnings', 'endpoints', 'redirectUris', 'postLogoutUris', 'keys', 'usableKeys', 'settings'],
  )
  for (const value of Object.values(report.summary)) assert.equal(Number.isInteger(value), true)
})

test('checked is the sum of the subject counts, in every report', async () => {
  for (const build of CORPUS) {
    const { summary } = await build()
    assert.equal(
      summary.checked,
      summary.endpoints + summary.redirectUris + summary.postLogoutUris + summary.keys + summary.settings,
    )
  }
})

test('the summary counts the severities the findings actually carry', async () => {
  // The falsifiable half of the severity contract at this level: a consumer
  // reading only `summary.errors` is reading a claim about the findings beside
  // it, and that claim can be wrong in a way a table compared against itself
  // never shows.
  for (const build of CORPUS) {
    const report = await build()
    assert.equal(report.summary.errors, report.findings.filter((row) => row.severity === 'error').length)
    assert.equal(report.summary.warnings, report.findings.filter((row) => row.severity === 'warning').length)
    assert.equal(
      report.status === 'fail',
      report.summary.errors > 0 && report.status !== 'incomplete',
      'fail is exactly an error-severity finding on a run that finished',
    )
  }
})

test('a rule id outside the table throws rather than defaulting to a severity', () => {
  assert.throws(
    () => createFinding({ ruleId: 'invented-rule', file: 'client.json', pointer: '', message: 'x' }),
    /not in RULE_SEVERITY/,
  )
})

test('the same bytes produce the same report twice over', async () => {
  const files = fixture({
    jwks: jwks([rsaKey('b'), rsaKey('a', { alg: 'BS256' })]),
    metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'ES256', 'none'] }),
  })

  const first = await apiReport(files)
  const second = await apiReport(files)
  assert.equal(JSON.stringify(first, null, 2), JSON.stringify(second, null, 2))
  assert.equal(first.findings.length > 2, true, 'a report with nothing in it would prove nothing')
})
