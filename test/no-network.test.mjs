import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import test from 'node:test'
import { promisify } from 'node:util'

import { CLI, clean, client, fixture, metadata, policy, projectDirectory, withRoot } from './support.mjs'

const execFileAsync = promisify(execFile)

/**
 * "It never contacts an issuer and opens no socket", checked without opening
 * a listener in the test suite either.
 *
 * This is the load-bearing claim of the whole package: the discovery document
 * and the key set are copies somebody saved, and a tool that quietly fetched
 * the live ones would be doing something the README promises it cannot. Three
 * independent checks, because each of them can be true while the property is
 * false:
 *
 * 1. A module resolution hook that refuses every network builtin, with the
 *    binary run under it over a real configuration. If any code path reached for
 *    a socket, the import would fail and the run would not produce a report. A
 *    control run proves the hook actually fires, because a guard that never
 *    fires proves nothing.
 * 2. A URL-bearing fixture run under that guard and a blocked global fetch:
 *    the issuer is read and compared while both network paths are denied.
 * 3. A scan of the shipped source for the globals and spellings a hook cannot
 *    see -- `fetch`, `eval`, a child process that would open a socket on this
 *    package's behalf, and anything that would read a credential.
 */

const NETWORK_MODULES = [
  'net', 'http', 'https', 'http2', 'dgram', 'dns', 'tls', 'cluster', 'quic', 'inspector',
]

const HOOK_SOURCE = `
const blocked = new Set(${JSON.stringify(NETWORK_MODULES)})
export async function resolve(specifier, context, next) {
  const bare = specifier.startsWith('node:') ? specifier.slice(5) : specifier
  if (blocked.has(bare.split('/')[0])) throw new Error('BLOCKED_NETWORK_IMPORT:' + specifier)
  return next(specifier, context)
}
`

const GUARD_SOURCE = `
import { register } from 'node:module'
register('./hook.mjs', import.meta.url)
globalThis.fetch = async () => { throw new Error('BLOCKED_NETWORK_FETCH') }
`

const PROBE_SOURCE = `
import net from 'node:net'
process.stdout.write(typeof net)
`

const FETCH_GUARD_PROBE_SOURCE = `
try {
  await fetch('data:text/plain,probe')
  throw new Error('fetch guard absent')
} catch (error) {
  if (error.message !== 'BLOCKED_NETWORK_FETCH') throw error
}
process.stdout.write('guarded')
`

async function withGuard(body) {
  const directory = await mkdtemp(join(tmpdir(), 'oidc-configuration-checker-guard-'))
  try {
    await writeFile(join(directory, 'hook.mjs'), HOOK_SOURCE)
    await writeFile(join(directory, 'guard.mjs'), GUARD_SOURCE)
    await writeFile(join(directory, 'probe.mjs'), PROBE_SOURCE)
    await writeFile(join(directory, 'fetch-guard-probe.mjs'), FETCH_GUARD_PROBE_SOURCE)
    return await body({ directory, guard: pathToFileURL(join(directory, 'guard.mjs')).href })
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

test('the binary completes a real run with every network builtin refused at resolution', async () => {
  await withGuard(async ({ directory, guard }) => {
    // The control first: a script that does reach for a socket must fail under
    // the same guard, or this case would pass on a hook that never fires.
    await assert.rejects(
      () => execFileAsync(process.execPath, ['--import', guard, join(directory, 'probe.mjs')]),
      /BLOCKED_NETWORK_IMPORT:node:net/,
    )

    const { stdout } = await withRoot(clean(), (root) =>
      execFileAsync(process.execPath, ['--import', guard, CLI, '--root', root, '--json']))

    const report = JSON.parse(stdout)
    assert.equal(report.status, 'pass')
    assert.equal(report.summary.checked, 11)
  })
})

test('an issuer URL is compared as local data while network imports and fetch are denied', async () => {
  await withGuard(async ({ directory, guard }) => {
    const { stdout: guardEvidence } = await execFileAsync(process.execPath, [
      '--import', guard, join(directory, 'fetch-guard-probe.mjs'),
    ])
    assert.equal(guardEvidence, 'guarded')
    const issuer = 'http://127.0.0.1:9'
    const files = fixture({
      metadata: metadata({ issuer }),
      client: client({ expectedIssuer: issuer, redirectUris: [`${issuer}/callback`] }),
      policy: policy({ allowedRedirectUris: [`${issuer}/callback`] }),
    })
    const run = await withRoot(files, async (root) => {
      try {
        return await execFileAsync(process.execPath, ['--import', guard, CLI, '--root', root, '--json'])
      } catch (error) {
        assert.equal(error.code, 1, 'the known http issuer is a real finding, not a usage refusal')
        return error
      }
    })
    const { stdout } = run
    const report = JSON.parse(stdout)
    assert.equal(report.profile.issuerMatches, true, 'the local issuer value reached the comparison')
    assert.equal(report.findings.some((finding) => finding.ruleId === 'issuer-not-https'), true)
  })
})

async function shippedSource() {
  const parts = []
  for (const directory of ['bin', 'src']) {
    for (const name of (await readdir(join(projectDirectory, directory))).sort()) {
      parts.push(await readFile(join(projectDirectory, directory, name), 'utf8'))
    }
  }
  return parts.join(String.fromCharCode(10))
}

test('the shipped source reaches for nothing that could open a socket', async () => {
  const source = await shippedSource()

  for (const name of NETWORK_MODULES) {
    assert.equal(source.includes(`node:${name}`), false, `the source imports node:${name}`)
  }
  for (const name of ['XMLHttpRequest', 'WebSocket', 'EventSource', 'sendBeacon', 'node:child_process', 'node:worker_threads', 'node:vm']) {
    assert.equal(source.includes(name), false, `the source reaches for ${name}`)
  }
  assert.equal(/\bfetch\s*\(/.test(source), false, 'the source calls fetch')
  assert.equal(/\bnew\s+Request\b/.test(source), false)
  assert.equal(/\beval\s*\(/.test(source), false)
  assert.equal(/\bnew\s+Function\b/.test(source), false)
})

test('the shipped source never reads a credential from anywhere', async () => {
  const source = await shippedSource()

  for (const name of ['process.stdin', 'node:readline', 'process.env', 'getPassword', 'prompt(']) {
    assert.equal(source.includes(name), false, `the source reaches for ${name}`)
  }
  // The four documents are the only inputs, and the file system is reached
  // through exactly one import whose bindings are all read-only. Listing the
  // verbs that must be absent would pass on a prose mention and fail on one;
  // naming the bindings that are present is the assertion that means something.
  const fsImports = source.match(/import \{[^}]*\} from 'node:fs[^']*'/g) ?? []
  assert.deepEqual(fsImports, ["import { readFile, realpath, stat } from 'node:fs/promises'"])
  assert.equal(/from 'node:fs'/.test(source), false, 'no synchronous file system surface either')
})

test('the only other builtins the package imports are the ones it declares', async () => {
  const source = await shippedSource()
  const imports = [...source.matchAll(/from '(node:[^']+)'/g)].map((match) => match[1])

  assert.deepEqual(
    [...new Set(imports)].sort(),
    ['node:buffer', 'node:crypto', 'node:fs/promises', 'node:path', 'node:perf_hooks', 'node:process'],
  )
})

test('the manifest declares no dependency of any kind', async () => {
  const manifest = JSON.parse(await readFile(join(projectDirectory, 'package.json'), 'utf8'))

  assert.equal(Object.hasOwn(manifest, 'dependencies'), false)
  assert.equal(Object.hasOwn(manifest, 'devDependencies'), false)
  assert.equal(Object.hasOwn(manifest, 'peerDependencies'), false)
  assert.equal(Object.hasOwn(manifest, 'optionalDependencies'), false)
  assert.equal(manifest.version, '0.1.0')
  assert.equal(manifest.engines.node, '>=22')
})
