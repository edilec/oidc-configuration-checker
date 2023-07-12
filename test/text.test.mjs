import assert from 'node:assert/strict'
import test from 'node:test'

import {
  byCodeUnit,
  decodeUtf8,
  describeValue,
  excerpt,
  hasForbiddenCharacter,
  isBase64Url,
  isIdentifier,
  isPlainObject,
  isResponseType,
  isToken,
} from '../src/index.mjs'
import { inspectEndpoint, inspectRedirectUri } from '../src/uri.mjs'
import { FORBIDDEN } from './support.mjs'

/** The primitives every other module leans on, exercised directly. */

test('byCodeUnit orders by code unit, including where collation disagrees', () => {
  assert.equal(byCodeUnit('ES256', 'EdDSA') < 0, true)
  assert.equal(byCodeUnit('RS256', 'none') < 0, true)
  assert.equal(byCodeUnit('Z', 'a') < 0, true)
  assert.equal(byCodeUnit('same', 'same'), 0)
})

test('every class the report contract names is detected', () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    assert.equal(hasForbiddenCharacter(`before${character}after`), true, name)
  }
  assert.equal(hasForbiddenCharacter('https://id.example.invalid/auth?x=1#y'), false)
  assert.equal(hasForbiddenCharacter('a b c'), false, 'a plain space is not a control character')
  assert.equal(hasForbiddenCharacter('a\tb'), true, 'tab is C0, and an identifier gets no second pass')
})

test('excerpt flattens, strips and bounds', () => {
  assert.equal(excerpt(`a${FORBIDDEN['C0 LF']}b`), 'a b')
  assert.equal(excerpt(`a${FORBIDDEN['C1 CSI']}b`), 'a b')
  assert.equal(excerpt(`a${FORBIDDEN['bidi RLO']}b`), 'a b')
  assert.equal(excerpt('  spaced   out  '), 'spaced out')
  assert.equal(excerpt('x'.repeat(300)).length, 163)
  assert.equal(excerpt('x'.repeat(300)).endsWith('...'), true)
})

test('an identifier is bounded, control-free and drawn from the documented alphabet', () => {
  assert.equal(isIdentifier('2026-03-signing'), true)
  assert.equal(isIdentifier('sig/2026+1='), true)
  assert.equal(isIdentifier(''), false)
  assert.equal(isIdentifier('x'.repeat(121)), false)
  assert.equal(isIdentifier('-leading'), false)
  assert.equal(isIdentifier('has space'), false)
  assert.equal(isIdentifier(`kid${FORBIDDEN['line separator']}`), false)
  assert.equal(isIdentifier(7), false)
})

test('a token is narrower than an identifier, as a registry value should be', () => {
  assert.equal(isToken('RS256'), true)
  assert.equal(isToken('P-256'), true)
  assert.equal(isToken('private_key_jwt'), true)
  assert.equal(isToken('x'.repeat(65)), false)
  assert.equal(isToken('a/b'), false)
})

test('a response type is one or more tokens separated by single spaces', () => {
  assert.equal(isResponseType('code'), true)
  assert.equal(isResponseType('code id_token'), true)
  assert.equal(isResponseType('code  id_token'), false)
  assert.equal(isResponseType(' code'), false)
  assert.equal(isResponseType('code '), false)
})

test('base64url is checked before it is decoded', () => {
  assert.equal(isBase64Url('AQAB'), true)
  assert.equal(isBase64Url('a-b_cd'), true)
  assert.equal(isBase64Url('not base64'), false)
  assert.equal(isBase64Url('AQA='), false, 'padding is not part of base64url here')
  assert.equal(isBase64Url('AQABCD'), true)
  assert.equal(isBase64Url('AQABC'), false, 'a length of 1 mod 4 encodes no whole final byte')
  assert.equal(isBase64Url('A'), false)
  assert.equal(isBase64Url('A'.repeat(1025)), false)
})

test('a refused value is described rather than reproduced', () => {
  assert.equal(describeValue(undefined), 'nothing')
  assert.equal(describeValue(null), 'null')
  assert.equal(describeValue(true), 'true')
  assert.equal(describeValue(7), 'an integer')
  assert.equal(describeValue(7.5), 'a number')
  assert.equal(describeValue('secret'), 'a string of 6 character(s)')
  assert.equal(describeValue([1, 2]), 'an array of 2 item(s)')
  assert.equal(describeValue({}), 'an object')
})

test('decoding is the decoder decision, never an inference from decoded text', () => {
  assert.deepEqual(decodeUtf8(new Uint8Array([0x7b, 0x7d])), { ok: true, text: '{}' })
  assert.equal(decodeUtf8(new Uint8Array([0xff, 0xfe, 0xfd])).ok, false)
  // A file that legitimately holds U+FFFD decodes; a tool that hunted for that
  // character in the decoded text would call this one undecodable.
  assert.equal(decodeUtf8(new TextEncoder().encode('"\\ufffd"')).ok, true)
})

test('isPlainObject refuses arrays, null and anything with another prototype', () => {
  assert.equal(isPlainObject({}), true)
  assert.equal(isPlainObject(Object.create(null)), true)
  assert.equal(isPlainObject([]), false)
  assert.equal(isPlainObject(null), false)
  assert.equal(isPlainObject(new Map()), false)
})

test('a redirect URI is judged on the raw string where the parser would hide the answer', () => {
  assert.deepEqual(inspectRedirectUri('https://app.example.invalid/*'), { ok: false, reason: 'wildcard' })
  assert.equal(inspectRedirectUri('https://app.example.invalid/cb#').notes.includes('fragment'), true)
  assert.equal(inspectRedirectUri('https://a@app.example.invalid/cb').notes.includes('userinfo'), true)
  assert.deepEqual(inspectRedirectUri('/relative'), { ok: false, reason: 'not-absolute' })
  assert.deepEqual(inspectRedirectUri(''), { ok: false, reason: 'empty' })
  assert.deepEqual(inspectRedirectUri(42), { ok: false, reason: 'not-a-string' })
  assert.deepEqual(inspectRedirectUri('https://app.example.invalid/a b'), { ok: false, reason: 'whitespace' })
  assert.deepEqual(inspectRedirectUri(`https://app.example.invalid/${FORBIDDEN['C0 NUL']}`), { ok: false, reason: 'forbidden-character' })
  assert.deepEqual(inspectRedirectUri(`https://app.example.invalid/${'x'.repeat(2100)}`), { ok: false, reason: 'too-long' })
})

test('an endpoint reports its transport, its origin and the components an issuer may not carry', () => {
  const plain = inspectEndpoint('https://id.example.invalid/token')
  assert.equal(plain.https, true)
  assert.equal(plain.origin, 'https://id.example.invalid')
  assert.equal(plain.hasQuery, false)
  assert.equal(plain.hasFragment, false)

  assert.equal(inspectEndpoint('http://id.example.invalid/token').https, false)
  assert.equal(inspectEndpoint('https://id.example.invalid/?a=1').hasQuery, true)
  assert.equal(inspectEndpoint('https://id.example.invalid/#a').hasFragment, true)
  assert.equal(inspectEndpoint('id.example.invalid').ok, false)
})
