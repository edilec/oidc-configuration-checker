import assert from 'node:assert/strict'
import test from 'node:test'

import { CLIENT_KEYS, CLIENT_REQUIRED, POLICY_KEYS, POLICY_REQUIRED } from '../src/index.mjs'
import { apiReport, client, clean, findingsFor, fixture, jwks, metadata, policy, raisedRules, rsaKey } from './support.mjs'

/**
 * Document shapes.
 *
 * The split that matters: a document this tool defines refuses an unknown key,
 * and the discovery document reports one and keeps reading. Both directions are
 * pinned here, because either one turned into the other is a defect -- a typo
 * that disables a check, or a checker that rejects every real provider.
 */

test('an unknown key in a document this tool defines refuses the document', async () => {
  for (const [name, document, ruleId] of [
    ['client.json', { ...client(), clientSecret: 'unused' }, 'client-invalid'],
    ['policy.json', { ...policy(), allowedScopes: [] }, 'policy-invalid'],
  ]) {
    const report = await apiReport(fixture(name === 'client.json' ? { client: document } : { policy: document }))
    const finding = findingsFor(report, ruleId)[0]
    assert.equal(finding.location.file, name)
    assert.equal(finding.message.includes('refused rather than ignored'), true)
    assert.equal(report.status, 'incomplete', 'a document that was refused is a document nothing was learned from')
  }
})

test('a one-character typo in a policy key is refused, not ignored', async () => {
  const typo = policy()
  typo.minimumKey = typo.minimumKeys
  delete typo.minimumKeys
  const report = await apiReport(fixture({ policy: typo }))

  assert.deepEqual(raisedRules(report), ['policy-invalid'])
  assert.equal(report.status, 'incomplete')
})

test('a schema version this build does not implement is refused rather than guessed at', async () => {
  for (const version of ['2', 1, undefined]) {
    const document = client()
    if (version === undefined) delete document.schemaVersion
    else document.schemaVersion = version
    const report = await apiReport(fixture({ client: document }))
    assert.equal(findingsFor(report, 'schema-version-unsupported').length, 1, String(version))
  }
})

test('a document that is not an object at all is refused by name', async () => {
  const cases = [
    ['metadata.json', 'metadata-invalid'],
    ['client.json', 'client-invalid'],
    ['policy.json', 'policy-invalid'],
    ['jwks.json', 'document-invalid'],
  ]
  for (const [name, ruleId] of cases) {
    const report = await apiReport({ ...clean(), [name]: ['not a document'] })
    assert.equal(findingsFor(report, ruleId).length, 1, name)
    assert.equal(report.status, 'incomplete', name)
  }
})

test('a key set carrying anything beside its keys is refused unread', async () => {
  const report = await apiReport(fixture({ jwks: { keys: [rsaKey('a')], private_keys: [{ d: 'x' }] } }))

  const finding = findingsFor(report, 'document-invalid')[0]
  assert.equal(finding.message.includes('"private_keys"'), true)
  assert.equal(JSON.stringify(report).includes('"d"'), false)
  assert.equal(report.status, 'incomplete')
})

test('a key set whose keys member is not an array is refused', async () => {
  const report = await apiReport(fixture({ jwks: { keys: { '0': rsaKey('a') } } }))

  assert.equal(findingsFor(report, 'document-invalid')[0].location.pointer, '/keys')
})

test('a key that is not an object is refused and counted', async () => {
  const report = await apiReport(fixture({ jwks: jwks([rsaKey('good'), 'a key']) }))

  assert.equal(findingsFor(report, 'jwk-invalid')[0].location.pointer, '/keys/1')
  assert.equal(report.summary.keys, 1, 'a refused key is not evaluated')
  assert.equal(report.status, 'incomplete')
})

test('every required client field is reported by name when it is absent', async () => {
  const empty = { schemaVersion: '1' }
  const report = await apiReport(fixture({ client: empty }))

  const missing = findingsFor(report, 'client-field-missing')
  assert.equal(missing.length, CLIENT_REQUIRED.length - 1, 'schemaVersion is present, the rest are not')
  for (const field of CLIENT_REQUIRED) {
    if (field === 'schemaVersion') continue
    assert.equal(missing.some((finding) => finding.message.includes(`"${field}"`)), true, field)
  }
})

test('every required policy field is reported by name when it is absent', async () => {
  const report = await apiReport(fixture({ policy: { schemaVersion: '1' } }))

  const missing = findingsFor(report, 'policy-field-missing')
  assert.equal(missing.length, POLICY_REQUIRED.length - 1)
})

test('every required key is one the document also declares as known', () => {
  for (const field of CLIENT_REQUIRED) assert.equal(CLIENT_KEYS.includes(field), true, field)
  for (const field of POLICY_REQUIRED) assert.equal(POLICY_KEYS.includes(field), true, field)
})

test('a field of the wrong type is described rather than echoed', async () => {
  const report = await apiReport(fixture({ client: client({ clientId: { name: 'storefront' } }) }))

  const finding = findingsFor(report, 'client-invalid')[0]
  assert.equal(finding.message.includes('it is an object'), true)
  assert.equal(JSON.stringify(report).includes('storefront'), false)
})

test('a policy integer outside its documented range is refused', async () => {
  for (const [field, value] of [['minimumKeys', -1], ['minRsaModulusBits', 256], ['minRsaModulusBits', 2048.5]]) {
    const report = await apiReport(fixture({ policy: policy({ [field]: value }) }))
    assert.equal(findingsFor(report, 'policy-invalid')[0].location.pointer, `/${field}`, `${field} ${value}`)
  }
})

test('a policy boolean that is not a boolean is refused', async () => {
  const report = await apiReport(fixture({ policy: policy({ requirePkceS256: 'yes' }) }))

  assert.equal(findingsFor(report, 'policy-invalid')[0].location.pointer, '/requirePkceS256')
})

test('a list entry that is not a usable registry value is refused by index', async () => {
  const report = await apiReport(fixture({
    metadata: metadata({ id_token_signing_alg_values_supported: ['RS256', 42] }),
  }))

  assert.equal(findingsFor(report, 'metadata-invalid')[0].location.pointer, '/id_token_signing_alg_values_supported/1')
  assert.equal(report.status, 'incomplete')
})

test('a list that is not a list at all is refused whole', async () => {
  const report = await apiReport(fixture({ client: client({ responseTypes: 'code' }) }))

  assert.equal(findingsFor(report, 'client-invalid')[0].location.pointer, '/responseTypes')
  assert.equal(report.status, 'incomplete')
})

test('a description longer than this build reads is refused, and not printed', async () => {
  const report = await apiReport(fixture({ client: client({ description: 'd'.repeat(301) }) }))

  assert.equal(findingsFor(report, 'client-invalid')[0].location.pointer, '/description')
  assert.equal(JSON.stringify(report).includes('dddddddddd'), false)
})
