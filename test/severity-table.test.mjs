import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import { RULE_SEVERITY } from '../src/index.mjs'
import { projectDirectory } from './support.mjs'

/**
 * The table against the documented catalog, in both directions.
 *
 * Worth having, and **not** the test. A table, a catalog and a hand-written
 * expected map are three declarations, and one edit that changes all three
 * leaves every assertion that compares them satisfied -- a sibling tool had 40
 * of its 52 error rules survive exactly that flip. What pins severity here is
 * `test/severity-exit.test.mjs` and `test/severity-word.test.mjs`: real inputs
 * through the real binary, with literal exit codes and counts.
 *
 * What this file is for is the other failure: a rule that exists in the code and
 * nowhere in the documentation, or a documented rule the code cannot emit.
 */

const DOC = join(projectDirectory, 'docs/oidc-rules.md')

async function documentedRules() {
  const text = await readFile(DOC, 'utf8')
  const rules = new Map()
  for (const line of text.split('\n')) {
    const match = /^\| `([a-z0-9-]+)` \| (error|warning|info) \|/.exec(line)
    if (match !== null) rules.set(match[1], match[2])
  }
  return rules
}

test('every rule in the table is documented with the same severity', async () => {
  const documented = await documentedRules()

  for (const [ruleId, severity] of Object.entries(RULE_SEVERITY)) {
    assert.equal(documented.get(ruleId), severity, `${ruleId} is documented as ${documented.get(ruleId)}`)
  }
})

test('every documented rule is in the table', async () => {
  const documented = await documentedRules()

  assert.equal(documented.size > 50, true, 'the catalog must have been parsed for this to prove anything')
  for (const ruleId of documented.keys()) {
    assert.equal(Object.hasOwn(RULE_SEVERITY, ruleId), true, `${ruleId} is documented and not in the table`)
  }
  assert.equal(documented.size, Object.keys(RULE_SEVERITY).length)
})

test('the table is frozen, ordered, and holds only the three severities', () => {
  assert.equal(Object.isFrozen(RULE_SEVERITY), true)
  const ids = Object.keys(RULE_SEVERITY)
  assert.deepEqual(ids, [...ids].sort(), 'the table reads in the order the catalog does')
  for (const severity of Object.values(RULE_SEVERITY)) {
    assert.equal(['error', 'info', 'warning'].includes(severity), true, severity)
  }
})

test('every rule id the source can emit is in the table', async () => {
  const sources = ['src/checks.mjs', 'src/documents.mjs', 'src/index.mjs']
  const emitted = new Set()
  for (const name of sources) {
    const text = await readFile(join(projectDirectory, name), 'utf8')
    for (const match of text.matchAll(/ruleId: '([a-z0-9-]+)'/g)) emitted.add(match[1])
    for (const match of text.matchAll(/ruleId: spec\.(\w+)/g)) assert.notEqual(match[1], '', 'indirect rule ids are resolved at run time')
  }

  assert.equal(emitted.size > 40, true, `only ${emitted.size} literal rule ids were found`)
  for (const ruleId of emitted) {
    assert.equal(Object.hasOwn(RULE_SEVERITY, ruleId), true, `${ruleId} is emitted and not in the table`)
  }
})
