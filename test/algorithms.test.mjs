import assert from 'node:assert/strict'
import test from 'node:test'

import {
  ALGORITHMS,
  KEY_TYPES,
  NONE_ALGORITHM,
  bitLengthOf,
  byteLengthOf,
  classifyAlgorithm,
  coordinateBytesFor,
  inspectKeyMaterial,
  privateParametersIn,
} from '../src/index.mjs'
import { EC_P256, RSA_1024, RSA_2048 } from './support.mjs'

/**
 * The registry and the measurements, exercised directly.
 *
 * The registry being a closed list is the point: an algorithm outside it comes
 * back `unrecognised`, which every caller turns into "unsupported", never into
 * "permitted" and never into "refused".
 */

test('none is never in the registry', () => {
  assert.equal(Object.hasOwn(ALGORITHMS, NONE_ALGORITHM), false)
  assert.deepEqual(classifyAlgorithm(NONE_ALGORITHM), { kind: 'none' })
})

test('a name in the registry comes back with the key it needs', () => {
  assert.deepEqual(classifyAlgorithm('RS256'), { kind: 'known', name: 'RS256', kty: 'RSA', curves: null, symmetric: false })
  assert.deepEqual(classifyAlgorithm('ES256').curves, ['P-256'])
  assert.deepEqual(classifyAlgorithm('EdDSA').curves, ['Ed25519', 'Ed448'])
  assert.equal(classifyAlgorithm('HS256').symmetric, true)
})

test('anything else is unrecognised, including a near miss and a non-string', () => {
  for (const name of ['BS256', 'rs256', 'RS255', '', undefined, null, 7, {}]) {
    assert.deepEqual(classifyAlgorithm(name), { kind: 'unrecognised' }, String(name))
  }
})

test('classifyAlgorithm cannot be reached through the prototype chain', () => {
  assert.deepEqual(classifyAlgorithm('toString'), { kind: 'unrecognised' })
  assert.deepEqual(classifyAlgorithm('constructor'), { kind: 'unrecognised' })
})

test('a modulus is measured, not assumed, and leading zero bytes do not count', () => {
  assert.equal(bitLengthOf(RSA_2048.n), 2048)
  assert.equal(bitLengthOf(RSA_1024.n), 1024)

  const padded = Buffer.concat([Buffer.alloc(64), Buffer.from(RSA_1024.n, 'base64url')]).toString('base64url')
  assert.equal(bitLengthOf(padded), 1024, 'padding a short key does not lengthen it')
  assert.equal(bitLengthOf('AQAB'), 17)
  assert.equal(bitLengthOf('not base64!'), null)
  assert.equal(bitLengthOf(undefined), null)
})

test('a coordinate is measured in bytes, and every supported curve has a size', () => {
  assert.equal(byteLengthOf(EC_P256.x), 32)
  assert.equal(coordinateBytesFor('P-256'), 32)
  assert.equal(coordinateBytesFor('P-384'), 48)
  assert.equal(coordinateBytesFor('P-521'), 66)
  assert.equal(coordinateBytesFor('Ed25519'), 32)
  assert.equal(coordinateBytesFor('Ed448'), 57)
  assert.equal(coordinateBytesFor('secp256k1'), 32)
  assert.equal(coordinateBytesFor('P-999'), null, 'an unknown curve leaves the size unanswered, not answered wrongly')
})

test('every curve named by a registry entry has a coordinate size', () => {
  for (const [name, entry] of Object.entries(ALGORITHMS)) {
    if (entry.curves === null) continue
    for (const curve of entry.curves) {
      assert.notEqual(coordinateBytesFor(curve), null, `${name} names ${curve}`)
    }
  }
})

test('every key type a registry entry needs is one this build inspects', () => {
  for (const entry of Object.values(ALGORITHMS)) {
    assert.equal(KEY_TYPES.includes(entry.kty), true, entry.kty)
  }
})

test('key material problems are named by parameter, never by value', () => {
  assert.deepEqual(inspectKeyMaterial({ n: RSA_2048.n, e: 'AQAB' }, 'RSA').problems, [])
  assert.equal(inspectKeyMaterial({ n: RSA_2048.n, e: 'AQAB' }, 'RSA').modulusBits, 2048)

  assert.deepEqual(inspectKeyMaterial({ e: 'AQAB' }, 'RSA').problems, [{ parameter: 'n', reason: 'missing' }])
  assert.deepEqual(inspectKeyMaterial({ n: 7, e: 'AQAB' }, 'RSA').problems, [{ parameter: 'n', reason: 'not-a-string' }])
  assert.deepEqual(inspectKeyMaterial({ n: '!!', e: 'AQAB' }, 'RSA').problems, [{ parameter: 'n', reason: 'not-base64url' }])
  assert.deepEqual(inspectKeyMaterial({ n: 'A'.repeat(2000), e: 'AQAB' }, 'RSA').problems, [{ parameter: 'n', reason: 'too-long' }])
  assert.deepEqual(inspectKeyMaterial({ x: EC_P256.x }, 'EC').problems, [{ parameter: 'y', reason: 'missing' }])
  assert.equal(inspectKeyMaterial({ x: EC_P256.x, y: EC_P256.y }, 'EC').coordinateBytes, 32)
})

test('private parameters are found under every key type at once, and never read', () => {
  assert.deepEqual(privateParametersIn({ kty: 'RSA', n: 'x', d: 'x', p: 'x' }), ['d', 'p'])
  assert.deepEqual(privateParametersIn({ kty: 'RSA', qi: 'x', dq: 'x', dp: 'x' }), ['dp', 'dq', 'qi'])
  assert.deepEqual(privateParametersIn({ kty: 'RSA', k: 'x' }), ['k'], 'a symmetric parameter is caught on a key that claims to be RSA')
  assert.deepEqual(privateParametersIn({ kty: 'EC', x: 'x', y: 'x' }), [])
})
