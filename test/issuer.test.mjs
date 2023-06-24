import assert from 'node:assert/strict'
import test from 'node:test'

import { ISSUER, apiReport, clean, client, findingsFor, fixture, metadata, raisedRules } from './support.mjs'

/**
 * Issuer alignment: the confused-deputy check.
 *
 * An ID token means nothing except relative to the issuer that minted it, so a
 * client configured to trust one issuer while reading the discovery document of
 * another will accept a token that was never about it. The comparison is exact,
 * as OpenID Connect Core requires of the "iss" claim.
 */

test('a clean configuration reports the issuer as matching', async () => {
  const report = await apiReport(clean())

  assert.equal(report.status, 'pass')
  assert.equal(report.profile.issuer, ISSUER)
  assert.equal(report.profile.expectedIssuer, ISSUER)
  assert.equal(report.profile.issuerMatches, true)
})

test('an issuer the client does not expect is reported against the client', async () => {
  const report = await apiReport(fixture({ metadata: metadata({ issuer: 'https://login.example.invalid' }) }))

  const finding = findingsFor(report, 'issuer-mismatch')[0]
  assert.equal(finding.location.file, 'client.json')
  assert.equal(finding.location.pointer, '/expectedIssuer')
  assert.equal(finding.evidence, 'provider https://login.example.invalid vs client https://id.example.invalid')
  assert.equal(report.profile.issuerMatches, false)
})

test('a difference of one trailing slash is reported as itself, not as a mismatch', async () => {
  const report = await apiReport(fixture({ client: client({ expectedIssuer: `${ISSUER}/` }) }))

  assert.deepEqual(raisedRules(report), ['issuer-trailing-slash'])
  assert.equal(report.profile.issuerMatches, false)
  assert.equal(findingsFor(report, 'issuer-mismatch').length, 0)
})

test('an http issuer is reported and still compared', async () => {
  const report = await apiReport(fixture({
    metadata: metadata({ issuer: 'http://id.example.invalid' }),
    client: client({ expectedIssuer: 'http://id.example.invalid' }),
  }))

  assert.equal(findingsFor(report, 'issuer-not-https').length, 1)
  assert.equal(report.profile.issuerMatches, true, 'the transport finding does not stop the comparison')
})

test('an issuer carrying a query or a fragment is refused by the discovery rules', async () => {
  for (const issuer of [`${ISSUER}?tenant=one`, `${ISSUER}#tenant`]) {
    const report = await apiReport(fixture({ metadata: metadata({ issuer }), client: client({ expectedIssuer: issuer }) }))
    assert.equal(findingsFor(report, 'issuer-invalid').length, 1, issuer)
  }
})

test('an issuer that is not a URL at all is never compared to anything', async () => {
  const report = await apiReport(fixture({ metadata: metadata({ issuer: 'id.example.invalid' }) }))

  assert.equal(findingsFor(report, 'issuer-invalid')[0].location.file, 'metadata.json')
  assert.equal(report.profile.issuer, null)
  assert.equal(report.profile.issuerMatches, null, 'unknown is recorded as unknown, never as false')
  assert.equal(findingsFor(report, 'issuer-mismatch').length, 0)
})

test('an issuer that is not a string is refused before any comparison', async () => {
  const report = await apiReport(fixture({ metadata: metadata({ issuer: 42 }) }))

  assert.equal(findingsFor(report, 'metadata-invalid')[0].location.pointer, '/issuer')
  assert.equal(report.profile.issuerMatches, null)
  assert.equal(report.status, 'incomplete')
})

test('an endpoint on another origin is reported without being judged', async () => {
  const report = await apiReport(fixture({
    metadata: metadata({ jwks_uri: 'https://keys.example.invalid/jwks' }),
  }))

  const finding = findingsFor(report, 'endpoint-origin-differs')[0]
  assert.equal(finding.severity, 'warning')
  assert.equal(finding.evidence, 'issuer https://id.example.invalid vs endpoint https://keys.example.invalid')
  assert.equal(report.status, 'pass', 'a warning does not withhold the pass')
})

test('an http endpoint fails', async () => {
  const report = await apiReport(fixture({ metadata: metadata({ token_endpoint: 'http://id.example.invalid/token' }) }))

  assert.equal(findingsFor(report, 'endpoint-not-https').length, 1)
  assert.equal(report.status, 'fail')
})

test('every declared endpoint is counted, and only the declared ones', async () => {
  const report = await apiReport(fixture({
    metadata: metadata({ userinfo_endpoint: `${ISSUER}/userinfo`, end_session_endpoint: `${ISSUER}/logout` }),
  }))

  assert.equal(report.summary.endpoints, 5)
  assert.equal(report.status, 'pass')
})

test('a discovery document missing a member a relying party needs is a verdict, not a gap', async () => {
  const incomplete = metadata()
  delete incomplete.jwks_uri
  delete incomplete.token_endpoint
  const report = await apiReport(fixture({ metadata: incomplete }))

  assert.equal(findingsFor(report, 'metadata-field-missing').length, 2)
  assert.equal(report.status, 'fail', 'the member is absent, which is known; nothing here is unknown')
})

test('a member this build does not recognise is reported and the document is still read', async () => {
  const report = await apiReport(fixture({ metadata: metadata({ tenant_id: 'storefront' }) }))

  const finding = findingsFor(report, 'metadata-key-unknown')[0]
  assert.equal(finding.severity, 'info')
  assert.equal(finding.location.pointer, '/tenant_id')
  assert.equal(report.status, 'pass')
  assert.equal(report.profile.issuerMatches, true, 'the rest of the document was still read')
})
