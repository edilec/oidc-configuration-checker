/**
 * Fixtures and runners shared by the test suite.
 *
 * Two entry points are exercised throughout: `apiReport` calls the exported
 * function, and `cliRun` spawns the real binary and reads the real exit code.
 * Several guarantees in this package can only be pinned by the second -- an
 * exit code cannot be satisfied by editing a table.
 *
 * Everything here builds *inputs*. Nothing here decides what a test expects: no
 * severity, no rule id, no count and no ordering lives in this file, so a test
 * cannot accidentally assert a value against the same declaration that produced
 * it.
 *
 * The key material below is public. Each modulus and each coordinate came from
 * a key pair generated once for this repository whose private half was never
 * written down; they are here so that structural checks -- modulus size, curve
 * and coordinate agreement -- run against real encodings rather than against
 * strings that merely look like them. No fixture in this package carries a
 * private key, a client secret or any other credential.
 */

import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { checkOidcConfiguration } from '../src/index.mjs'

const execFileAsync = promisify(execFile)

export const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const CLI = join(projectDirectory, 'bin/oidc-configuration-checker.mjs')

/** A 2048-bit RSA public key. */
export const RSA_2048 = Object.freeze({ n: "1tZIulCCJ4rlzNOruT63vrGVpjpYL8Fr9C9MkgWjzR2hzwHUGWH6N1MOsnHhxi5BV2ub0Go9Wna1R7eQlzdnmYWmU6ZvjMxqtk2yWqGmSXXxwffa-zREm63TFOFv8n9AIkISc_aOEjSknD0y8Lr62XMknLUCEjL69-KzGjQEpP4YkaEIUj2NM9j9xN9c_tBiWC5jXIezW_9QwrBPaDmg81FbdTgc2aDtxU29evnNjATYeZOHnL9E7DL5ZN-D38OfAUTufVG9BSBGXubbfLq_V7-XVFImX7Sr1XQCODGEv4tH-i_yMFPceK7fzCA-RUFH75ubDkoznHzwz1_Junn15w", e: "AQAB" })

/** A second 2048-bit RSA public key, so a rotation can be staged in a fixture. */
export const RSA_2048_NEXT = Object.freeze({ n: "l6iSK-uryVJ7mdN6gc82HYm2Xd0p_iLA52V1JcsmGgRFlitXolqJJh60pApUthP33_J1Nmgf1kuihyvQMTPK8hqNAtCMh1vMg2wu34_z3jJaMDdUai6TFXYkdSeEa3Bmxe7pgKq1GC4xAQzll2H14SWIdWOM8t15g4hC3_VY3ZetqLXcEBdPvd2svUQZCck9cU2VPxJKDQrkLjXpu-U3NB7xh3_buERVQrlUuVmow834DOFPrP0LakQ_SPnlB9Al8F0Vpmey02SrOtHy3ELGJeTnzi1CF9rRNj2z7t4B6gL3x7ezSys4VIzTrhowiq71kN6o-jhAaN33Jy8fKxA8yQ", e: "AQAB" })

/** A 1024-bit RSA public key, for the modulus floor. */
export const RSA_1024 = Object.freeze({ n: "4Cx2ctdynXf3ht2NSusWWl_3Oqi3qLejE4cOplz2kDdjoOKugMhf30rZ7C8FC0xlEZdxxubWaoAmYn_SGROco8lfCR0MkI9fHzLqC3_-PwnIvJMEa_In2xxdJ3RYVS2V-X8lIDq-Z_zc32TqIMlLC_VyvODde9P9IPKHkCm6_sM", e: "AQAB" })

/** A P-256 public key. */
export const EC_P256 = Object.freeze({ crv: "P-256", x: "HxDVKL82qXyLEnmROibnseUHakT-XUlLYlzePrZdYrs", y: "VHFACFifrporNhX3aQYumS36RfEp1cpQISErsLIZEsU" })

/** An Ed25519 public key. */
export const OKP_ED25519 = Object.freeze({ crv: "Ed25519", x: "WPzVBMcyj2zXPiWgjvZ3wBNsAAzkH5ocPMs6EsjpM4E" })

export function rsaKey(kid, overrides = {}) {
  const key = { kty: 'RSA', use: 'sig', alg: 'RS256', n: RSA_2048.n, e: RSA_2048.e, ...overrides }
  if (kid !== undefined) key.kid = kid
  return key
}

export function ecKey(kid, overrides = {}) {
  const key = { kty: 'EC', use: 'sig', alg: 'ES256', crv: EC_P256.crv, x: EC_P256.x, y: EC_P256.y, ...overrides }
  if (kid !== undefined) key.kid = kid
  return key
}

export const ISSUER = 'https://id.example.invalid'
export const CALLBACK = 'https://app.example.invalid/auth/callback'
export const SIGNED_OUT = 'https://app.example.invalid/signed-out'

/** A discovery document as a provider publishes one. */
export function metadata(overrides = {}) {
  const issuer = overrides.issuer ?? ISSUER
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['private_key_jwt'],
    code_challenge_methods_supported: ['S256'],
    ...overrides,
  }
}

/** The relying-party settings document this tool defines. */
export function client(overrides = {}) {
  return {
    schemaVersion: '1',
    clientId: 'storefront-web',
    expectedIssuer: ISSUER,
    redirectUris: [CALLBACK],
    postLogoutRedirectUris: [SIGNED_OUT],
    responseTypes: ['code'],
    idTokenSignedResponseAlg: 'RS256',
    tokenEndpointAuthMethod: 'private_key_jwt',
    pkceMethod: 'S256',
    ...overrides,
  }
}

/** The policy document this tool defines. */
export function policy(overrides = {}) {
  return {
    schemaVersion: '1',
    redirectUriMatching: 'exact',
    allowedRedirectUris: [CALLBACK],
    allowedPostLogoutRedirectUris: [SIGNED_OUT],
    allowedIdTokenSigningAlgs: ['RS256'],
    allowedResponseTypes: ['code'],
    allowedTokenEndpointAuthMethods: ['private_key_jwt'],
    requirePkceS256: true,
    minimumKeys: 1,
    minRsaModulusBits: 2048,
    ...overrides,
  }
}

export const jwks = (keys) => ({ keys })

/** The four documents, as objects, under their default names. */
export const fixture = (parts = {}) => ({
  'metadata.json': parts.metadata ?? metadata(),
  'client.json': parts.client ?? client(),
  'jwks.json': parts.jwks ?? jwks([rsaKey('2026-03-signing')]),
  'policy.json': parts.policy ?? policy(),
})

/**
 * A configuration that raises nothing at all. Tests break exactly one thing in
 * it so that the finding they assert is the only finding there is.
 */
export const clean = () => fixture()

/**
 * Create a temporary root, write the named files into it, run `body(root)`, and
 * remove the tree afterwards whatever happened.
 *
 * A string is written verbatim and a `Uint8Array` byte for byte, so a test can
 * plant text that is not JSON, or bytes that are not UTF-8 at all.
 */
export async function withRoot(files, body) {
  const root = await mkdtemp(join(tmpdir(), 'oidc-configuration-checker-'))
  try {
    for (const [name, content] of Object.entries(files)) {
      const bytes = typeof content === 'string' || content instanceof Uint8Array
        ? content
        : `${JSON.stringify(content, null, 2)}\n`
      await writeFile(join(root, name), bytes)
    }
    return await body(root)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

/** Run the exported API over a temporary root. */
export async function apiReport(files, options = {}) {
  return withRoot(files, (root) => checkOidcConfiguration({ root, ...options }))
}

/** Spawn the real binary. Returns the exit code and both streams; never throws on a non-zero exit. */
export async function cliRun(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, ...args], { cwd: projectDirectory })
    return { code: 0, stdout, stderr }
  } catch (error) {
    return { code: error.code, stdout: error.stdout ?? '', stderr: error.stderr ?? '' }
  }
}

/** Spawn the real binary over a temporary root, and parse whatever stdout carried. */
export async function cliReport(files, extraArgs = []) {
  return withRoot(files, async (root) => {
    const result = await cliRun(['--root', root, '--json', ...extraArgs])
    return { ...result, report: result.stdout === '' ? null : JSON.parse(result.stdout) }
  })
}

/** Every rule id a report raised, deduplicated and ordered by code unit. */
export const raisedRules = (report) =>
  [...new Set(report.findings.map((finding) => finding.ruleId))].sort()

/** The findings for one rule id, in emitted order. */
export const findingsFor = (report, ruleId) => report.findings.filter((finding) => finding.ruleId === ruleId)

/** One row of the profile. */
export const keyRow = (report, kid) => report.profile.signingKeys.find((row) => row.kid === kid)
export const uriRow = (report, uri) => report.profile.redirectUris.find((row) => row.uri === uri)

/**
 * One character from each class the report contract names, built from code
 * points so every test file that uses them stays plain ASCII and readable.
 */
export const FORBIDDEN = Object.freeze({
  'C0 NUL': String.fromCharCode(0x00),
  'C0 LF': String.fromCharCode(0x0a),
  'C0 ESC': String.fromCharCode(0x1b),
  DEL: String.fromCharCode(0x7f),
  'C1 NEL': String.fromCharCode(0x85),
  'C1 CSI': String.fromCharCode(0x9b),
  'line separator': String.fromCharCode(0x2028),
  'paragraph separator': String.fromCharCode(0x2029),
  'bidi LRM': String.fromCharCode(0x200e),
  'bidi RLM': String.fromCharCode(0x200f),
  'bidi RLO': String.fromCharCode(0x202e),
  'bidi isolate': String.fromCharCode(0x2066),
})
