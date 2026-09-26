import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_LIMITS, PRIVATE_PARAMETERS, RULE_SEVERITY, byCodeUnit } from '../src/index.mjs'

/**
 * The three ordering sites that cannot be pinned, proved equivalent instead of
 * left as gaps.
 *
 * `test/ordering.test.mjs` pins ten of this package's thirteen ordering sites by
 * emitting a sequence a collator would emit differently. The remaining three
 * order values drawn from alphabets on which code-unit order and English
 * collation agree on every pair -- rule ids over `[a-z0-9-]`, this package's own
 * limit names, and the JWK private parameter names. Substituting a collator at
 * those three sites is an *equivalent* mutation: the output cannot change, so no
 * test can catch it, and saying so with an enumeration is more honest than
 * either claiming coverage or leaving a gap.
 *
 * Each case below enumerates every ordered pair of the real values and asserts
 * that the two comparisons agree in sign. Each also pins the alphabet the proof
 * rests on, so that a value added later in a different shape fails this test
 * rather than quietly widening it.
 */

const collator = new Intl.Collator('en')

function everyOrderedPairAgrees(values, label) {
  let compared = 0
  for (const left of values) {
    for (const right of values) {
      const mine = Math.sign(byCodeUnit(left, right))
      const collated = Math.sign(collator.compare(left, right))
      assert.equal(mine, collated, `${label}: "${left}" vs "${right}" would move under collation`)
      compared += 1
    }
  }
  return compared
}

test('every ordered pair of real rule ids collates exactly as it compares by code unit', () => {
  const ruleIds = Object.keys(RULE_SEVERITY)

  assert.equal(ruleIds.length > 50, true, 'the catalog must be the real one for this to prove anything')
  for (const ruleId of ruleIds) assert.match(ruleId, /^[a-z][a-z0-9-]*[a-z0-9]$/, 'the alphabet this proof rests on')
  assert.equal(everyOrderedPairAgrees(ruleIds, 'rule id'), ruleIds.length ** 2)
})

test('every ordered pair of real limit names collates exactly as it compares by code unit', () => {
  const names = Object.keys(DEFAULT_LIMITS)

  assert.equal(names.length, 8)
  for (const name of names) assert.match(name, /^max[A-Z][A-Za-z]*$/, 'the alphabet this proof rests on')
  assert.equal(everyOrderedPairAgrees(names, 'limit name'), names.length ** 2)
})

test('every ordered pair of private parameter names collates exactly as it compares by code unit', () => {
  assert.equal(PRIVATE_PARAMETERS.length, 8)
  for (const name of PRIVATE_PARAMETERS) assert.match(name, /^[a-z]{1,3}$/, 'the alphabet this proof rests on')
  assert.equal(everyOrderedPairAgrees(PRIVATE_PARAMETERS, 'private parameter'), PRIVATE_PARAMETERS.length ** 2)
})

/**
 * The counter-example, so the three cases above are not read as "collation is
 * harmless here".
 *
 * These are the real values the pinned sites order, and every one of them moves
 * under collation. The difference between the two groups is the alphabet, not
 * the comparator.
 */
test('the values the pinned sites order do move under collation', () => {
  for (const [left, right] of [['ES256', 'EdDSA'], ['RS256', 'none'], ['Z-2026', 'a-2026']]) {
    assert.equal(Math.sign(byCodeUnit(left, right)), -1)
    assert.equal(Math.sign(collator.compare(left, right)), 1, `${left} vs ${right}`)
  }
})
