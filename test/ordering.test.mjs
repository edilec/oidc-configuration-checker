import assert from 'node:assert/strict'
import test from 'node:test'

import { checkOidcConfiguration, validateLimits } from '../src/index.mjs'
import {
  apiReport,
  client,
  clean,
  findingsFor,
  fixture,
  jwks,
  metadata,
  policy,
  rsaKey,
  RSA_2048_NEXT,
} from './support.mjs'

/**
 * Ordering, pinned by what the tool emits.
 *
 * A source scan for `.localeCompare(` is not a determinism test: `Intl.Collator`
 * collates identically and spells differently, so the scan passes while the
 * output silently starts depending on the ICU data of whichever Node build is
 * running. Pinning the comparator itself is no better -- every call site can be
 * swapped on its own, and there are thirteen of them in this package.
 *
 * Every case below chooses inputs an English collator orders the other way
 * round, pushes them through the real report path, and asserts the exact
 * emitted sequence, so that swapping any one site fails a test rather than
 * going unnoticed. The collator is constructed here and asserted to disagree,
 * which is what makes these cases cases at all.
 *
 * Algorithm names are where this matters most, and they need no contrived
 * fixture to show it: by code unit `ES256` precedes `EdDSA` and both precede
 * `none`; an English collator puts `EdDSA` first and `none` in the middle.
 *
 * Three sites cannot be pinned this way because their real values -- rule ids
 * over [a-z-], this package's own limit names, and the JWK private parameter
 * names -- collate identically to their code points. Those are proved
 * equivalent by enumeration in `test/ordering-equivalence.test.mjs` rather than
 * left as gaps.
 */

const collator = new Intl.Collator('en')
const disagrees = (left, right) => {
  assert.equal(left < right, true, `${left} precedes ${right} by code unit`)
  assert.equal(collator.compare(left, right) > 0, true, `a collator puts ${right} first, which is what makes this a case`)
}

test('the disagreements every case below relies on are real', () => {
  disagrees('ES256', 'EdDSA')
  disagrees('RS256', 'none')
  disagrees('Z-2026', 'a-2026')
  disagrees('Z.json', 'a.json')
  disagrees('Zed', 'alpha')
  disagrees('https://app.example.invalid/Z-callback', 'https://app.example.invalid/a-callback')
  disagrees('/Zextra', '/aextra')
})

test('the algorithms a provider offers are listed by code unit', async () => {
  const report = await apiReport(fixture({
    metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'EdDSA', 'ES256'] }),
    policy: policy({ allowedIdTokenSigningAlgs: ['RS256', 'EdDSA', 'ES256'] }),
  }))

  assert.deepEqual(report.profile.algorithms.offered, ['ES256', 'EdDSA', 'RS256'])
  assert.notDeepEqual(
    report.profile.algorithms.offered,
    [...report.profile.algorithms.offered].sort((left, right) => collator.compare(left, right)),
    'a collator would order this list differently',
  )
})

test('the algorithms a policy permits are listed by code unit', async () => {
  const report = await apiReport(fixture({
    metadata: metadata({ id_token_signing_alg_values_supported: ['RS256'] }),
    policy: policy({ allowedIdTokenSigningAlgs: ['RS256', 'EdDSA', 'ES256'] }),
  }))

  assert.deepEqual(report.profile.algorithms.permitted, ['ES256', 'EdDSA', 'RS256'])
})

test('the redirect URIs in the profile are ordered by code unit', async () => {
  const uris = ['https://app.example.invalid/a-callback', 'https://app.example.invalid/Z-callback']
  const report = await apiReport(fixture({
    client: client({ redirectUris: uris }),
    policy: policy({ allowedRedirectUris: uris }),
  }))

  assert.deepEqual(
    report.profile.redirectUris.map((row) => row.uri),
    ['https://app.example.invalid/Z-callback', 'https://app.example.invalid/a-callback'],
  )
})

test('the post-logout URIs in the profile are ordered by code unit, on their own', async () => {
  const uris = ['https://app.example.invalid/a-bye', 'https://app.example.invalid/Z-bye']
  const report = await apiReport(fixture({
    client: client({ postLogoutRedirectUris: uris }),
    policy: policy({ allowedPostLogoutRedirectUris: uris }),
  }))

  assert.deepEqual(
    report.profile.postLogoutUris.map((row) => row.uri),
    ['https://app.example.invalid/Z-bye', 'https://app.example.invalid/a-bye'],
  )
})

test('the key set in the profile is ordered by key id, by code unit', async () => {
  const report = await apiReport(fixture({
    jwks: jwks([rsaKey('a-2026'), rsaKey('Z-2026', { n: RSA_2048_NEXT.n })]),
  }))

  assert.deepEqual(report.profile.signingKeys.map((row) => row.kid), ['Z-2026', 'a-2026'])
})

test('the unknown keys named in one message are ordered by code unit', async () => {
  const report = await apiReport(fixture({ client: { ...client(), alpha: 1, Zed: 2 } }))

  assert.equal(findingsFor(report, 'client-invalid')[0].message.includes('unknown key(s) "Zed", "alpha"'), true)
})

test('findings are ordered by file first, by the names the caller gave', async () => {
  const files = {
    'Z.json': metadata({ tenant: 'one' }),
    'a.json': { ...client(), Zed: 1 },
    'jwks.json': jwks([rsaKey('signing')]),
    'policy.json': policy(),
  }
  const report = await apiReport(files, { metadata: 'Z.json', client: 'a.json' })

  assert.deepEqual(
    report.findings.map((finding) => [finding.location.file, finding.ruleId]),
    [['Z.json', 'metadata-key-unknown'], ['a.json', 'client-invalid']],
  )
  const asCollated = [...report.findings].sort((left, right) => collator.compare(left.location.file, right.location.file))
  assert.notDeepEqual(
    asCollated.map((finding) => finding.location.file),
    report.findings.map((finding) => finding.location.file),
  )
})

/**
 * The pointer sits between the file and the rule id in the documented sort key,
 * and nothing else pins that it is there at all.
 *
 * Collapsing the chain so that the rule id decides first leaves the file case
 * above satisfied, and so does dropping the pointer entirely. The two findings
 * below share a file and a rule id and differ only in pointer, so the emitted
 * sequence says which key the report is really ordered by.
 */
test('findings sharing a file are ordered by pointer', async () => {
  const report = await apiReport(fixture({ metadata: metadata({ aextra: 1, Zextra: 2 }) }))

  assert.deepEqual(
    report.findings.map((finding) => finding.location.pointer),
    ['/Zextra', '/aextra'],
  )
  assert.deepEqual(
    [...new Set(report.findings.map((finding) => finding.ruleId))],
    ['metadata-key-unknown'],
    'both findings must share a rule id, or the rule key would be doing the work',
  )
})

test('findings sharing a file, a pointer and a rule are ordered by message, by code unit', async () => {
  const report = await apiReport(fixture({
    metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'EdDSA', 'ES256'] }),
    policy: policy({ allowedIdTokenSigningAlgs: ['RS256'] }),
  }))

  const findings = findingsFor(report, 'alg-offered-not-permitted')
  assert.equal(findings.length, 2)
  assert.deepEqual(
    findings.map((finding) => finding.location.pointer),
    ['/id_token_signing_alg_values_supported', '/id_token_signing_alg_values_supported'],
  )
  assert.equal(findings[0].message.includes('offers "ES256"'), true)
  assert.equal(findings[1].message.includes('offers "EdDSA"'), true)
  assert.equal(collator.compare(findings[0].message, findings[1].message) > 0, true, 'a collator would emit them the other way round')
})

test('which unknown limit is reported first is decided by code unit', () => {
  // Declared alpha-first on purpose: insertion order is what an unsorted walk
  // would follow, and collation would follow it too.
  assert.throws(() => validateLimits({ alpha: 1, Zed: 1 }), /Unknown limit "Zed"/)
})

test('which unknown option is reported first is decided by code unit', async () => {
  await assert.rejects(() => checkOidcConfiguration({ alpha: 1, Zed: 1, root: '.' }), /Unknown option "Zed"/)
})

test('the same inputs produce byte-identical stdout twice over', async () => {
  const files = fixture({
    metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 'EdDSA', 'ES256'], Zextra: 1, aextra: 2 }),
    jwks: jwks([rsaKey('a-2026'), rsaKey('Z-2026', { n: RSA_2048_NEXT.n })]),
  })

  const first = await apiReport(files)
  const second = await apiReport(files)
  assert.equal(JSON.stringify(first, null, 2), JSON.stringify(second, null, 2))
  assert.equal(first.findings.length > 2, true, 'a report with nothing in it would prove nothing')
})

test('a clean run raises nothing, so every case above is the only thing it changed', async () => {
  const report = await apiReport(clean())
  assert.deepEqual(report.findings, [])
})
