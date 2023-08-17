import assert from 'node:assert/strict'
import test from 'node:test'

import { CALLBACK, apiReport, cliReport, client, findingsFor, fixture, policy, raisedRules, uriRow } from './support.mjs'

/**
 * Redirect policy: exact matching, and the shapes that only make sense without
 * it.
 *
 * The whole reason this tool compares one string against another is that prefix
 * and pattern matching is how an authorization response is delivered to a host
 * nobody registered. A checker that mirrored the loose behaviour could not
 * detect the loose behaviour.
 */

const withUris = (clientUris, allowedUris) => fixture({
  client: client({ redirectUris: clientUris }),
  policy: policy({ allowedRedirectUris: allowedUris }),
})

test('a registered URI the policy allows exactly is allowlisted', async () => {
  const report = await apiReport(withUris([CALLBACK], [CALLBACK]))

  assert.equal(report.status, 'pass')
  assert.equal(uriRow(report, CALLBACK).status, 'allowlisted')
  assert.equal(report.summary.redirectUris, 1)
})

test('a URI that differs from the allowlist only by a trailing slash does not match', async () => {
  const report = await apiReport(withUris([`${CALLBACK}/`], [CALLBACK]))

  assert.deepEqual(raisedRules(report), ['redirect-uri-not-allowlisted', 'redirect-uri-unused'])
  assert.equal(uriRow(report, `${CALLBACK}/`).status, 'not-allowlisted')
})

test('long redirect collision evidence and profile identity distinguish exact values in both directions', async () => {
  const left = `https://app.example.invalid/${'a'.repeat(205)}X`
  const right = `https://app.example.invalid/${'a'.repeat(205)}Y`
  const control = await cliReport(withUris([left], [left]))
  assert.equal(control.code, 0)
  assert.equal(control.report.status, 'pass')
  assert.equal(control.report.profile.redirectUris[0].status, 'allowlisted')
  assert.match(control.report.profile.redirectUris[0].rawSha256, /^[a-f0-9]{64}$/)

  for (const [registered, allowed, registeredUnit, allowedUnit] of [
    [left, right, 'U+0058', 'U+0059'],
    [right, left, 'U+0059', 'U+0058'],
  ]) {
    const { code, report } = await cliReport(withUris([registered], [allowed]))
    assert.equal(code, 1)
    assert.equal(report.status, 'fail')
    const denied = findingsFor(report, 'redirect-uri-not-allowlisted')[0]
    const unused = findingsFor(report, 'redirect-uri-unused')[0]
    assert.equal(denied.location.pointer, '/redirectUris/0')
    assert.equal(unused.location.pointer, '/allowedRedirectUris/0')
    assert.equal(denied.evidence.includes(`raw UTF-16 offset ${left.length - 1}: client ${registeredUnit} vs policy ${allowedUnit}`), true)
    assert.equal(unused.evidence.includes(`raw UTF-16 offset ${left.length - 1}: policy ${allowedUnit} vs client ${registeredUnit}`), true)
    assert.match(report.profile.redirectUris[0].rawSha256, /^[a-f0-9]{64}$/)
    if (registered === left) assert.equal(report.profile.redirectUris[0].rawSha256, control.report.profile.redirectUris[0].rawSha256)
    else assert.notEqual(report.profile.redirectUris[0].rawSha256, control.report.profile.redirectUris[0].rawSha256)
  }
})

test('the profile URI identity marker starts only beyond the 200-unit display bound', async () => {
  const prefix = 'https://app.example.invalid/'
  const atBound = `${prefix}${'a'.repeat(200 - prefix.length)}`
  const overBound = `${atBound}X`
  const exact = await apiReport(withUris([atBound], [atBound]))
  const truncated = await apiReport(withUris([overBound], [overBound]))
  assert.equal(atBound.length, 200)
  assert.equal(exact.status, 'pass')
  assert.equal(truncated.status, 'pass')
  assert.equal(exact.profile.redirectUris[0].uri, atBound)
  assert.equal(Object.hasOwn(exact.profile.redirectUris[0], 'rawSha256'), false)
  assert.equal(truncated.profile.redirectUris[0].uri.endsWith('...'), true)
  assert.match(truncated.profile.redirectUris[0].rawSha256, /^[a-f0-9]{64}$/)
})

test('profile rows with identical long excerpts are ordered by the raw URI', async () => {
  const left = `https://app.example.invalid/${'a'.repeat(205)}X`
  const right = `https://app.example.invalid/${'a'.repeat(205)}Y`
  const ascending = await apiReport(withUris([left, right], [left, right]))
  const descending = await apiReport(withUris([right, left], [left, right]))
  assert.equal(ascending.status, 'pass')
  assert.equal(descending.status, 'pass')
  assert.equal(ascending.profile.redirectUris[0].uri, ascending.profile.redirectUris[1].uri)
  assert.notEqual(ascending.profile.redirectUris[0].rawSha256, ascending.profile.redirectUris[1].rawSha256)
  assert.deepEqual(descending.profile.redirectUris, ascending.profile.redirectUris)
})

test('a URI that differs only in letter case does not match, and the suggestion says why', async () => {
  const report = await apiReport(withUris(['https://APP.example.invalid/auth/callback'], [CALLBACK]))

  const finding = findingsFor(report, 'redirect-uri-not-allowlisted')[0]
  assert.equal(finding.location.pointer, '/redirectUris/0')
  assert.equal(finding.suggestion.includes('only in letter case'), true)
})

test('a URI the policy does not list at all names the list it is missing from', async () => {
  const report = await apiReport(withUris([CALLBACK, 'https://app.example.invalid/legacy'], [CALLBACK]))

  const finding = findingsFor(report, 'redirect-uri-not-allowlisted')[0]
  assert.equal(finding.location.pointer, '/redirectUris/1')
  assert.equal(finding.suggestion.includes('allowedRedirectUris'), true)
  assert.equal(report.status, 'fail')
})

test('an allowlist entry this client does not use is reported as spare, not as a failure', async () => {
  const report = await apiReport(withUris([CALLBACK], [CALLBACK, 'https://other.example.invalid/cb']))

  const finding = findingsFor(report, 'redirect-uri-unused')[0]
  assert.equal(finding.severity, 'info')
  assert.equal(finding.location.file, 'policy.json')
  assert.equal(finding.location.pointer, '/allowedRedirectUris/1')
  assert.equal(report.status, 'pass')
})

test('a wildcard is refused rather than expanded, and the run is not decided', async () => {
  const report = await apiReport(withUris([CALLBACK], [CALLBACK, 'https://app.example.invalid/*']))

  const finding = findingsFor(report, 'redirect-uri-wildcard')[0]
  assert.equal(finding.location.file, 'policy.json')
  assert.equal(finding.message.includes('refused to guess'), true)
  assert.equal(report.status, 'incomplete', 'coverage was decided against part of the allowlist, so it was not decided')
})

test('partial client or policy redirect lists never assert absence from a reduced index', async () => {
  const registered = 'https://app.example.invalid/a'
  const allowed = 'https://app.example.invalid/b'
  const complete = await cliReport(withUris([registered], [allowed]))
  assert.equal(complete.code, 1)
  assert.equal(complete.report.status, 'fail')
  assert.deepEqual(
    complete.report.findings.filter((finding) => finding.ruleId.startsWith('redirect-uri-')).map((finding) => finding.ruleId),
    ['redirect-uri-not-allowlisted', 'redirect-uri-unused'],
  )

  for (const missing of ['https://app.example.invalid/*', '/relative']) {
    for (const side of ['client', 'policy']) {
      const clientUris = side === 'client' ? [registered, missing] : [registered]
      const policyUris = side === 'policy' ? [allowed, missing] : [allowed]
      const { code, report } = await cliReport(withUris(clientUris, policyUris))
      assert.equal(code, 2, `${side}: missing evidence is incomplete`)
      assert.equal(report.status, 'incomplete')
      assert.equal(findingsFor(report, missing.includes('*') ? 'redirect-uri-wildcard' : 'redirect-uri-invalid').length, 1)
      assert.equal(findingsFor(report, 'redirect-uri-not-allowlisted').length, 0, `${side}: no policy absence claim`)
      assert.equal(findingsFor(report, 'redirect-uri-unused').length, 0, `${side}: no client absence claim`)
      assert.equal(report.profile.redirectUris[0].status, 'unknown')
    }
  }

  const present = await cliReport(withUris([registered], [registered, 'https://app.example.invalid/*']))
  assert.equal(present.code, 2)
  assert.equal(present.report.profile.redirectUris[0].status, 'allowlisted', 'a known exact presence remains known')
})

test('a policy that declares prefix matching fails, and the lists are still compared exactly', async () => {
  const report = await apiReport(fixture({ policy: policy({ redirectUriMatching: 'prefix' }) }))

  const finding = findingsFor(report, 'redirect-matching-not-exact')[0]
  assert.equal(finding.location.pointer, '/redirectUriMatching')
  assert.equal(report.status, 'fail')
  assert.equal(uriRow(report, CALLBACK).status, 'allowlisted', 'the exact comparison still happened')
})

test('a fragment, a userinfo component and an http host are each their own rule', async () => {
  const cases = [
    [`${CALLBACK}#done`, 'redirect-uri-fragment'],
    ['https://user@app.example.invalid/auth/callback', 'redirect-uri-userinfo'],
    ['http://app.example.invalid/auth/callback', 'redirect-uri-insecure-scheme'],
  ]

  for (const [uri, ruleId] of cases) {
    const report = await apiReport(withUris([uri], [uri]))
    assert.equal(findingsFor(report, ruleId).length, 2, `${ruleId} fires on the client list and on the policy list`)
    assert.equal(report.status, 'fail', uri)
  }
})

test('a loopback redirect URI is accepted, and the localhost spelling is only a warning', async () => {
  const literal = 'http://127.0.0.1:8765/callback'
  const accepted = await apiReport(withUris([literal], [literal]))
  assert.deepEqual(raisedRules(accepted), [])
  assert.equal(accepted.status, 'pass')

  const named = 'http://localhost:8765/callback'
  const warned = await apiReport(withUris([named], [named]))
  assert.deepEqual(raisedRules(warned), ['redirect-uri-loopback-hostname'])
  assert.equal(warned.status, 'pass')
})

test('a private-use scheme of the application own reverse-domain name is accepted', async () => {
  const uri = 'com.example.storefront:/oauth2redirect'
  const report = await apiReport(withUris([uri], [uri]))

  assert.deepEqual(raisedRules(report), [], 'RFC 8252 section 7.1 registers exactly this shape')
  assert.equal(report.status, 'pass')
})

test('a scheme any other application could also claim is not a private-use scheme', async () => {
  for (const uri of ['myapp:/callback', 'javascript:alert(1)']) {
    const report = await apiReport(withUris([uri], [uri]))
    assert.equal(findingsFor(report, 'redirect-uri-insecure-scheme').length, 2, uri)
  }
})

test('a repeated URI is counted once and reported once', async () => {
  const report = await apiReport(withUris([CALLBACK, CALLBACK], [CALLBACK]))

  assert.equal(findingsFor(report, 'redirect-uri-duplicate').length, 1)
  assert.equal(findingsFor(report, 'redirect-uri-duplicate')[0].location.pointer, '/redirectUris/1')
  assert.equal(report.summary.redirectUris, 1)
  assert.equal(report.status, 'fail')
})

test('a URI that could not be read is refused, never compared, and leaves the run undecided', async () => {
  const report = await apiReport(withUris([CALLBACK, '/auth/callback'], [CALLBACK]))

  const finding = findingsFor(report, 'redirect-uri-invalid')[0]
  assert.equal(finding.location.pointer, '/redirectUris/1')
  assert.equal(finding.message.includes('is not an absolute URI with a scheme'), true)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.profile.redirectUris.length, 1, 'a refused URI never enters the compared set')
})

test('post-logout URIs are compared against their own allowlist', async () => {
  const report = await apiReport(fixture({
    client: client({ postLogoutRedirectUris: ['https://app.example.invalid/bye'] }),
  }))

  assert.equal(findingsFor(report, 'redirect-uri-not-allowlisted')[0].location.pointer, '/postLogoutRedirectUris/0')
  assert.equal(report.summary.postLogoutUris, 1)
  assert.deepEqual(report.profile.postLogoutUris, [{ uri: 'https://app.example.invalid/bye', status: 'not-allowlisted' }])
})

test('a client that registers no redirect URI at all is missing a required field', async () => {
  const noUris = client()
  delete noUris.redirectUris
  const report = await apiReport(fixture({ client: noUris }))

  assert.equal(findingsFor(report, 'client-field-missing').length, 1)
  assert.equal(report.summary.redirectUris, 0)
  assert.equal(report.status, 'fail')
})
