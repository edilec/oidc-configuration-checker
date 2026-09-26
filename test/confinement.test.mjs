import assert from 'node:assert/strict'
import { mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { checkOidcConfiguration, isInside } from '../src/index.mjs'
import { apiReport, clean, cliRun, findingsFor, withRoot } from './support.mjs'

/**
 * Path confinement, and the false refusals a careless confinement causes.
 *
 * Rejecting `..` and absolute paths is not confinement: a symbolic link planted
 * inside the root contains no `..` at all and points anywhere. The real path of
 * both sides is resolved and compared, which catches the link -- and, just as
 * importantly, does not refuse a legitimate file under a root that is itself
 * reached through a link. On macOS `/var` is a link to `/private/var`, so a
 * temporary directory is exactly that case, and every other test in this suite
 * would fail if the root were not resolved too.
 *
 * This tool opens files for reading and writes nothing, so it has no output
 * path that could collide with an input. The dev/ino comparison a writing tool
 * needs has nothing to protect here; what it must not do is refuse a real
 * input, which is what the second and third cases below pin.
 */

test('isInside accepts the root itself and refuses a sibling with the same prefix', () => {
  assert.equal(isInside('/a/root', '/a/root'), true)
  assert.equal(isInside('/a/root', '/a/root/client.json'), true)
  assert.equal(isInside('/a/root', '/a/root-2/client.json'), false)
  assert.equal(isInside('/a/root/', '/a/root/client.json'), true)
})

test('a symbolic link planted inside the root is refused unread', async () => {
  const outside = await mkdtemp(join(tmpdir(), 'oidc-outside-'))
  try {
    await writeFile(join(outside, 'secret.json'), JSON.stringify({ schemaVersion: '1', stolen: true }))
    const files = clean()
    delete files['policy.json']

    const report = await withRoot(files, async (root) => {
      await symlink(join(outside, 'secret.json'), join(root, 'policy.json'))
      return checkOidcConfiguration({ root })
    })

    const finding = findingsFor(report, 'path-escapes-root')[0]
    assert.equal(finding.location.file, 'policy.json')
    assert.equal(JSON.stringify(report).includes('stolen'), false, 'nothing out of the tree was read')
    assert.equal(report.status, 'incomplete')
  } finally {
    await rm(outside, { recursive: true, force: true })
  }
})

test('a root reached through a symbolic link still reads its own files', async () => {
  const report = await apiReport(clean())

  assert.equal(report.status, 'pass', 'a temporary directory on macOS is reached through /var, which is a link')
  assert.equal(report.summary.keys, 1)
})

test('a symbolic link inside the root pointing at another file inside the root is read', async () => {
  const files = clean()
  const policy = files['policy.json']
  delete files['policy.json']
  files['policy-real.json'] = policy

  const report = await withRoot(files, async (root) => {
    await symlink(join(root, 'policy-real.json'), join(root, 'policy.json'))
    return checkOidcConfiguration({ root })
  })

  assert.equal(report.status, 'pass', 'confinement refuses what leaves the tree, not what stays in it')
})

test('an absolute path or a parent step is a configuration error, before any read', async () => {
  for (const name of ['/etc/hosts', '../outside.json', 'nested/../../outside.json']) {
    await assert.rejects(() => checkOidcConfiguration({ root: '.', policy: name }), /--policy must/, name)
  }
  const result = await cliRun(['--root', '.', '--jwks', '/etc/hosts'])
  assert.equal(result.code, 2)
  assert.equal(result.stdout, '', 'a configuration error never had a subject')
})

test('a file that is not there is missing evidence, named, and never a pass', async () => {
  const files = clean()
  delete files['jwks.json']
  const report = await apiReport(files)

  const finding = findingsFor(report, 'input-unreadable')[0]
  assert.equal(finding.location.file, 'jwks.json')
  assert.equal(finding.message.includes('ENOENT'), true)
  assert.equal(report.status, 'incomplete')
})

test('a directory where a document should be is not read as one', async () => {
  const files = clean()
  delete files['jwks.json']

  const report = await withRoot(files, async (root) => {
    await mkdtemp(join(root, 'jwks.json'))
    return checkOidcConfiguration({ root, jwks: (await readdir(root)).find((name) => name.startsWith('jwks.json')) })
  })

  assert.equal(findingsFor(report, 'input-unreadable')[0].message.includes('not a regular file'), true)
  assert.equal(report.status, 'incomplete')
})

test('a root that is not a directory, or is not there, is a configuration error', async () => {
  await assert.rejects(() => checkOidcConfiguration({ root: '/nowhere-at-all-here' }), /--root could not be resolved/)
  await assert.rejects(
    () => checkOidcConfiguration({ root: join(process.cwd(), 'package.json') }),
    /--root must be a directory/,
  )
})

test('a root that is not a string, and an unknown option, are refused before any read', async () => {
  await assert.rejects(() => checkOidcConfiguration({}), /root must be a non-empty string/)
  await assert.rejects(() => checkOidcConfiguration({ root: '.', jwksUri: 'x' }), /Unknown option "jwksUri"/)
  await assert.rejects(() => checkOidcConfiguration('.'), /options must be an object/)
})

test('bytes that are not UTF-8 are refused by the decoder, on any of the four inputs', async () => {
  for (const name of ['client.json', 'jwks.json', 'metadata.json', 'policy.json']) {
    const report = await apiReport({ ...clean(), [name]: new Uint8Array([0x7b, 0xff, 0x7d]) })
    const finding = findingsFor(report, 'input-not-utf8')[0]
    assert.equal(finding.location.file, name)
    assert.equal(report.status, 'incomplete', name)
  }
})

test('text that is not JSON is refused with the parser message, on any of the four inputs', async () => {
  for (const name of ['client.json', 'jwks.json', 'metadata.json', 'policy.json']) {
    const report = await apiReport({ ...clean(), [name]: '{ "schemaVersion": ' })
    assert.equal(findingsFor(report, 'input-not-json')[0].location.file, name)
    assert.equal(report.status, 'incomplete', name)
  }
})

test('the package writes nothing', async () => {
  const before = await withRoot(clean(), async (root) => {
    await checkOidcConfiguration({ root })
    const names = (await readdir(root)).sort()
    const bytes = {}
    for (const name of names) bytes[name] = await readFile(join(root, name), 'utf8')
    return { names, bytes }
  })

  assert.deepEqual(before.names, ['client.json', 'jwks.json', 'metadata.json', 'policy.json'])
  for (const content of Object.values(before.bytes)) assert.equal(content.endsWith('\n'), true)
})
