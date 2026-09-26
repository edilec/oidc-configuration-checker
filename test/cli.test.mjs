import assert from 'node:assert/strict'
import test from 'node:test'

import {
  clean,
  cliRun,
  client,
  fixture,
  jwks,
  metadata,
  policy,
  rsaKey,
  withRoot,
} from './support.mjs'

/**
 * The command line surface: the two streams, the four exit codes, and the flags.
 *
 * The stream contract is the one a consumer depends on. stdout carries the JSON
 * report and nothing else, so it pipes straight into a parser; stderr carries
 * the human summary and the diagnostics, so **a non-empty stderr is correct**.
 */

test('--help and --version print to stdout and exit 0', async () => {
  const help = await cliRun(['--help'])
  assert.equal(help.code, 0)
  assert.equal(help.stdout.startsWith('oidc-configuration-checker'), true)
  assert.equal(help.stdout.includes('--root DIR'), true)
  assert.equal(help.stdout.includes('never requests or reads a token'), true)
  assert.equal(help.stderr, '')

  const short = await cliRun(['-h'])
  assert.equal(short.stdout, help.stdout)

  const version = await cliRun(['--version'])
  assert.equal(version.code, 0)
  assert.equal(version.stdout, '0.1.0\n')
})

test('the documented version is the version in the manifest', async () => {
  const { readFile } = await import('node:fs/promises')
  const { join } = await import('node:path')
  const { projectDirectory } = await import('./support.mjs')

  const manifest = JSON.parse(await readFile(join(projectDirectory, 'package.json'), 'utf8'))
  const version = await cliRun(['--version'])
  assert.equal(version.stdout, `${manifest.version}\n`)
})

test('stdout carries the JSON report and nothing else', async () => {
  const result = await withRoot(clean(), (root) => cliRun(['--root', root]))

  const report = JSON.parse(result.stdout)
  assert.equal(report.tool, 'oidc-configuration-checker')
  assert.equal(result.stdout.endsWith('}\n'), true)
  assert.equal(result.stderr.length > 0, true, 'a non-empty stderr is correct, not an error')
  assert.equal(result.stderr.includes('issuer https://id.example.invalid: matches the client.'), true)
})

test('--json keeps the report and drops the human summary', async () => {
  const result = await withRoot(clean(), (root) => cliRun(['--root', root, '--json']))

  assert.equal(JSON.parse(result.stdout).status, 'pass')
  assert.equal(result.stderr, '')
})

test('an incomplete run says so on stderr, after the report', async () => {
  const files = clean()
  delete files['jwks.json']
  const result = await withRoot(files, (root) => cliRun(['--root', root, '--json']))

  assert.equal(result.code, 2)
  assert.equal(JSON.parse(result.stdout).status, 'incomplete')
  assert.equal(result.stderr.includes('incomplete: evidence was missing'), true, '--json still prints the one line that says it is not a pass')
})

test('each input can be named explicitly, and the report uses the name that was given', async () => {
  const files = {
    'discovery.json': metadata(),
    'rp.json': client(),
    'keys.json': jwks([rsaKey('signing')]),
    'rules.json': policy(),
  }
  const result = await withRoot(files, (root) => cliRun([
    '--root', root, '--json',
    '--metadata', 'discovery.json',
    '--client', 'rp.json',
    '--jwks', 'keys.json',
    '--policy', 'rules.json',
  ]))

  assert.equal(result.code, 0)
  assert.equal(JSON.parse(result.stdout).status, 'pass')
})

test('a document named explicitly and missing is reported under that name', async () => {
  const result = await withRoot(clean(), (root) => cliRun(['--root', root, '--json', '--jwks', 'keys.json']))

  const report = JSON.parse(result.stdout)
  assert.equal(report.findings[0].location.file, 'keys.json')
  assert.equal(result.code, 2)
})

test('a limit flag reaches the run, and a bad one is a configuration error', async () => {
  const enforced = await withRoot(
    fixture({ jwks: jwks([rsaKey('a'), rsaKey('b')]) }),
    (root) => cliRun(['--root', root, '--json', '--max-keys', '1']),
  )
  assert.equal(JSON.parse(enforced.stdout).findings[0].ruleId, 'too-many-keys')

  for (const args of [['--max-keys', '0'], ['--max-keys', 'many'], ['--max-keys'], ['--root']]) {
    const result = await cliRun(['--root', '.', ...args])
    assert.equal(result.code, 2, args.join(' '))
    assert.equal(result.stdout, '', args.join(' '))
  }
})

test('an unknown flag is refused with the help text, and stdout stays empty', async () => {
  const result = await cliRun(['--root', '.', '--max-key', '3'])

  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.equal(result.stderr.includes('Unknown option "--max-key"'), true)
  assert.equal(result.stderr.includes('Usage:'), true)
})

test('a flag that carries a value is accepted once', async () => {
  for (const args of [
    ['--metadata', 'a.json', '--metadata', 'b.json'],
    ['--max-keys', '1', '--max-keys', '2'],
  ]) {
    const result = await withRoot(clean(), (root) => cliRun(['--root', root, ...args]))
    assert.equal(result.code, 2, args.join(' '))
    assert.equal(result.stdout, '')
    assert.equal(result.stderr.includes('was given more than once'), true)
  }
})

test('--json may be repeated, because it carries no value to discard', async () => {
  const result = await withRoot(clean(), (root) => cliRun(['--root', root, '--json', '--json']))

  assert.equal(result.code, 0)
  assert.equal(result.stderr, '')
})

test('the human summary reports the same numbers as the report', async () => {
  const result = await withRoot(
    fixture({ jwks: jwks([rsaKey('a'), rsaKey('b', { alg: 'BS256' })]) }),
    (root) => cliRun(['--root', root]),
  )
  const report = JSON.parse(result.stdout)

  assert.equal(result.stderr.includes(`keys ${report.summary.usableKeys} of ${report.summary.keys} usable for rotation`), true)
  assert.equal(result.stderr.includes(`${report.summary.checked} subject(s) checked`), true)
  assert.equal(result.stderr.includes(`status ${report.status}.`), true)
})
