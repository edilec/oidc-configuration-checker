/**
 * oidc-configuration-checker -- check exported OpenID Connect discovery
 * metadata, relying-party settings and a published key set against an issuer,
 * redirect and key-rotation policy.
 *
 * Everything this package does, it does to four local files. It never contacts
 * an issuer, never requests or reads a token, never performs an authorization
 * flow and opens no socket at all. `README.md` lists in its own words what that
 * means it cannot tell you -- and the list is longer than the list of what it
 * can.
 *
 * Three properties are load-bearing and are pinned by behaviour rather than by
 * declaration:
 *
 * - **Unknown is never a pass.** An algorithm this build does not implement, a
 *   key type it cannot inspect, a URI it could not parse, an input it could not
 *   decode: each one leaves its subject out of every satisfied set and makes
 *   the run `incomplete`. A key whose algorithm nobody here implements is
 *   unsupported, which is not approved.
 * - **Redirect comparison is exact.** One string against another, with no
 *   prefix, wildcard, normalisation or case folding anywhere in the package.
 * - **Order is by code unit.** Algorithm names are exactly where code-unit
 *   order and locale collation disagree -- `EdDSA` against `ES256`, `none`
 *   against either -- so a collated report would list a provider's algorithms
 *   differently on a different machine.
 */

import { readFile, realpath, stat } from 'node:fs/promises'
import { dirname, isAbsolute, normalize, resolve, sep } from 'node:path'
import { performance } from 'node:perf_hooks'

import { compileClient, compileJwks, compileMetadata, compilePolicy } from './documents.mjs'
import { runChecks } from './checks.mjs'
import { byCodeUnit, decodeUtf8, excerpt, hasForbiddenCharacter, isPlainObject, parseFailureDetail } from './text.mjs'

export const TOOL_ID = 'oidc-configuration-checker'
export const REPORT_SCHEMA_VERSION = '1'

export const DEFAULT_METADATA_NAME = 'metadata.json'
export const DEFAULT_CLIENT_NAME = 'client.json'
export const DEFAULT_JWKS_NAME = 'jwks.json'
export const DEFAULT_POLICY_NAME = 'policy.json'

/**
 * Limits, each enforced and each reported by name when it is reached.
 *
 * Exceeding one is never a silent truncation: it produces a finding that names
 * the limit and marks the run `incomplete`, because a partial read is not
 * evidence about the part nobody read.
 */
export const DEFAULT_LIMITS = Object.freeze({
  maxAlgorithms: 64,
  maxFileBytes: 5242880,
  maxFindings: 1000,
  maxKeys: 100,
  maxListEntries: 32,
  maxMetadataKeys: 200,
  maxRedirectUris: 50,
  maxRuntimeMs: 10000,
})

/** A caller may lower a limit, never raise it past these caps. */
export const HARD_LIMITS = Object.freeze({
  maxAlgorithms: 512,
  maxFileBytes: 67108864,
  maxFindings: 20000,
  maxKeys: 5000,
  maxListEntries: 512,
  maxMetadataKeys: 5000,
  maxRedirectUris: 2000,
  maxRuntimeMs: 600000,
})

/**
 * The authoritative rule severity table.
 *
 * Severity is the whole difference between a run that fails and one that
 * passes. Written as a literal at each construction site it drifts silently,
 * and demoting one of the error rules below turns "this client trusts a
 * different issuer from the one it talks to" into a green build with every test
 * still passing. Every finding takes its severity from here, and an unknown
 * rule id throws.
 *
 * `test/severity-table.test.mjs` asserts this table against the documented
 * catalog in both directions. That is worth having and it is not the test: a
 * table, a catalog and a test's expected map are three declarations, and one
 * edit that changes all three leaves every assertion that compares them
 * satisfied. `test/severity-exit.test.mjs` and `test/severity-word.test.mjs`
 * drive real inputs through the real binary and pin the exit code, the error
 * count and the printed severity word with literal values instead.
 */
export const RULE_SEVERITY = Object.freeze({
  'alg-none-offered': 'error',
  'alg-none-permitted': 'error',
  'alg-none-selected': 'error',
  'alg-not-offered': 'error',
  'alg-not-permitted': 'error',
  'alg-offered-not-permitted': 'warning',
  'alg-symmetric-selected': 'warning',
  'alg-unrecognised': 'error',
  'auth-method-not-offered': 'error',
  'auth-method-not-permitted': 'error',
  'client-field-missing': 'error',
  'client-invalid': 'error',
  'document-invalid': 'error',
  'endpoint-invalid': 'error',
  'endpoint-not-https': 'error',
  'endpoint-origin-differs': 'warning',
  'input-not-json': 'error',
  'input-not-utf8': 'error',
  'input-too-large': 'error',
  'input-unreadable': 'error',
  'issuer-invalid': 'error',
  'issuer-mismatch': 'error',
  'issuer-not-https': 'error',
  'issuer-trailing-slash': 'error',
  'jwk-alg-key-mismatch': 'error',
  'jwk-alg-none': 'error',
  'jwk-alg-not-permitted': 'error',
  'jwk-alg-undeclared': 'error',
  'jwk-alg-unrecognised': 'error',
  'jwk-curve-mismatch': 'error',
  'jwk-invalid': 'error',
  'jwk-kid-duplicate': 'error',
  'jwk-kid-invalid': 'error',
  'jwk-kid-missing': 'error',
  'jwk-kty-unsupported': 'error',
  'jwk-member-unknown': 'info',
  'jwk-private-material': 'error',
  'jwk-rsa-modulus-short': 'error',
  'jwks-no-signing-key': 'error',
  'jwks-selected-alg-unusable': 'error',
  'jwks-too-few-keys': 'error',
  'metadata-field-missing': 'error',
  'metadata-invalid': 'error',
  'metadata-key-unknown': 'info',
  'no-checks-performed': 'error',
  'path-escapes-root': 'error',
  'pkce-not-s256': 'error',
  'pkce-s256-not-offered': 'error',
  'policy-field-missing': 'error',
  'policy-invalid': 'error',
  'redirect-matching-not-exact': 'error',
  'redirect-uri-duplicate': 'error',
  'redirect-uri-fragment': 'error',
  'redirect-uri-insecure-scheme': 'error',
  'redirect-uri-invalid': 'error',
  'redirect-uri-loopback-hostname': 'warning',
  'redirect-uri-not-allowlisted': 'error',
  'redirect-uri-unused': 'info',
  'redirect-uri-userinfo': 'error',
  'redirect-uri-wildcard': 'error',
  'response-type-not-offered': 'error',
  'response-type-not-permitted': 'error',
  'schema-version-unsupported': 'error',
  'time-budget-exceeded': 'error',
  'too-many-algorithms': 'error',
  'too-many-findings': 'error',
  'too-many-keys': 'error',
  'too-many-list-entries': 'error',
  'too-many-metadata-keys': 'error',
  'too-many-redirect-uris': 'error',
})

const MESSAGE_LIMIT = 400
const SUGGESTION_LIMIT = 300
const LOCATION_LIMIT = 200
const MAX_NAME_LENGTH = 200

const ALLOWED_OPTIONS = Object.freeze(['client', 'clock', 'jwks', 'limits', 'metadata', 'policy', 'root'])

/** The four inputs, in the order they are read. */
const INPUTS = Object.freeze(['client', 'jwks', 'metadata', 'policy'])

/** Raised when the run passes its time budget; turned into a finding by the caller. */
class TimeBudgetExceeded extends Error {}

/**
 * Validate limit overrides.
 *
 * An unknown key throws rather than being ignored. A documented limit that a
 * typo silently disables is a limit that is not enforced, and the CLI turns
 * this throw into a configuration error with an empty stdout.
 */
export function validateLimits(overrides = {}) {
  if (!isPlainObject(overrides)) throw new TypeError('limits must be an object')
  const limits = { ...DEFAULT_LIMITS }
  for (const key of Object.keys(overrides).sort(byCodeUnit)) {
    if (!Object.hasOwn(DEFAULT_LIMITS, key)) {
      throw new TypeError(`Unknown limit "${excerpt(key, 60)}"; known limits are ${Object.keys(DEFAULT_LIMITS).sort(byCodeUnit).join(', ')}`)
    }
    const value = overrides[key]
    const cap = HARD_LIMITS[key]
    if (!Number.isInteger(value) || value < 1 || value > cap) {
      throw new TypeError(`limits.${key} must be an integer between 1 and ${cap}`)
    }
    limits[key] = value
  }
  return Object.freeze(limits)
}

/**
 * True when `candidate` is the real root itself or lies beneath it.
 *
 * Both sides must already be real paths. Comparing a real root against a path
 * that has not been resolved refuses legitimate files whenever the root is
 * reached through a symbolic link -- a `/var` that is really `/private/var` is
 * enough -- and a false refusal is a defect too.
 */
export function isInside(root, candidate) {
  return candidate === root || candidate.startsWith(root.endsWith(sep) ? root : root + sep)
}

/**
 * A file name given on the command line, checked as configuration.
 *
 * Absolute paths and `..` segments are refused here, before any evidence is
 * gathered, because naming a file outside the declared root is a usage error
 * rather than a fact about the subject. This is emphatically *not* the
 * confinement: a symbolic link planted inside the root passes every check in
 * this function, and `resolveInput` is what catches it by resolving the real
 * path of both sides.
 */
function validateName(name, flag) {
  if (typeof name !== 'string' || name.length === 0 || name.length > MAX_NAME_LENGTH) {
    throw new TypeError(`${flag} must be a relative file name of 1-${MAX_NAME_LENGTH} characters`)
  }
  if (hasForbiddenCharacter(name)) {
    throw new TypeError(`${flag} must not contain a control, separator or bidi character`)
  }
  if (isAbsolute(name)) throw new TypeError(`${flag} must be relative to --root, not an absolute path`)
  const parts = normalize(name).split(/[\\/]/)
  if (parts.includes('..')) throw new TypeError(`${flag} must not step outside --root with ".."`)
  return name
}

class FindingSink {
  constructor() {
    this.rows = []
  }

  add(row) {
    this.rows.push({ pointer: '', ...row })
  }
}

/**
 * Build a finding, taking its severity from the one table.
 *
 * Every untrusted string is sanitised here -- file, pointer, message,
 * suggestion and evidence alike, not only the evidence field. A sibling tool
 * sanitised evidence carefully and left identifiers raw, so a record id holding
 * a newline forged an extra line in the human report.
 */
export function createFinding(row) {
  const severity = RULE_SEVERITY[row.ruleId]
  if (severity === undefined) {
    throw new Error(`Rule "${row.ruleId}" is not in RULE_SEVERITY; add it to the table and to docs/oidc-rules.md.`)
  }
  const finding = {
    ruleId: row.ruleId,
    severity,
    message: excerpt(row.message, MESSAGE_LIMIT),
    location: { file: excerpt(row.file, LOCATION_LIMIT), pointer: excerpt(row.pointer, LOCATION_LIMIT) },
  }
  if (row.evidence !== undefined && row.evidence !== '') finding.evidence = excerpt(row.evidence)
  if (row.suggestion !== undefined) finding.suggestion = excerpt(row.suggestion, SUGGESTION_LIMIT)
  return finding
}

/**
 * The documented sort key: `location.file`, `location.pointer`, `ruleId`,
 * `message`.
 *
 * The message is part of the key because two rules anchor more than one finding
 * at the same pointer on purpose -- an offered algorithm the policy does not
 * permit is a relation between two documents, so it belongs to the list rather
 * than to one index of it. No two findings share all four components, and
 * `sort` is stable, so even a tie would preserve emission order, which is
 * itself fixed by the documents.
 */
export function compareFindings(a, b) {
  return (
    byCodeUnit(a.location.file, b.location.file) ||
    byCodeUnit(a.location.pointer, b.location.pointer) ||
    byCodeUnit(a.ruleId, b.ruleId) ||
    byCodeUnit(a.message, b.message)
  )
}

function buildReport(sink, state, limits) {
  let findings = sink.rows.map((row) => createFinding(row)).sort(compareFindings)
  let truncated = false

  if (findings.length > limits.maxFindings) {
    const dropped = findings.length - limits.maxFindings + 1
    findings = findings.slice(0, limits.maxFindings - 1)
    findings.push(createFinding({
      file: state.files.policy,
      ruleId: 'too-many-findings',
      pointer: '',
      message: `The run produced more findings than the maxFindings limit of ${limits.maxFindings}; ${dropped} were not reported and this report is partial.`,
      suggestion: 'Raise --max-findings, or narrow the inputs.',
    }))
    findings.sort(compareFindings)
    truncated = true
  }

  let errors = 0
  let warnings = 0
  for (const finding of findings) {
    if (finding.severity === 'error') errors += 1
    else if (finding.severity === 'warning') warnings += 1
  }

  const counts = state.counts
  const checked = counts.endpoints + counts.redirectUris + counts.postLogoutUris + counts.keys + counts.settings
  const status = state.incomplete || truncated ? 'incomplete' : errors > 0 ? 'fail' : 'pass'

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: TOOL_ID,
    status,
    summary: {
      checked,
      errors,
      warnings,
      endpoints: counts.endpoints,
      redirectUris: counts.redirectUris,
      postLogoutUris: counts.postLogoutUris,
      keys: counts.keys,
      usableKeys: counts.usableKeys,
      settings: counts.settings,
    },
    profile: state.profile,
    findings,
  }
}

/**
 * Resolve one declared input inside the declared root.
 *
 * Both sides are resolved to their real paths before they are compared.
 * Rejecting `..` lexically -- which `validateName` also does -- is not
 * confinement: a symbolic link planted inside the root points anywhere and
 * contains no `..` at all. Equally, comparing a real root against an unresolved
 * target refuses legitimate files, so the root is resolved too.
 */
async function resolveInput(realRoot, name) {
  const target = resolve(realRoot, name)
  try {
    const real = await realpath(target)
    if (!isInside(realRoot, real)) return { ok: false, reason: 'escapes' }
    return { ok: true, real }
  } catch (error) {
    if (error.code !== 'ENOENT' && error.code !== 'ELOOP') return { ok: false, reason: 'unreadable', code: error.code }
    // The entry may still exist as a link that resolves nowhere. Confine the
    // nearest existing ancestor first, so a symlinked parent directory cannot
    // decide where a "missing" file would have been read from.
    try {
      const realParent = await realpath(dirname(target))
      if (!isInside(realRoot, realParent)) return { ok: false, reason: 'escapes' }
    } catch {
      return { ok: false, reason: 'unreadable', code: error.code }
    }
    return { ok: false, reason: 'unreadable', code: error.code }
  }
}

/** Read one confined input and turn it into parsed JSON, or into the finding that says why not. */
async function loadJson(sink, file, real, limits) {
  let info
  try {
    info = await stat(real)
  } catch (error) {
    sink.add({ file, ruleId: 'input-unreadable', message: `${file} could not be inspected: ${error.code ?? 'unknown error'}.` })
    return null
  }
  if (!info.isFile()) {
    sink.add({ file, ruleId: 'input-unreadable', message: `${file} is not a regular file, so nothing was read from it.` })
    return null
  }
  if (info.size > limits.maxFileBytes) {
    sink.add({
      file,
      ruleId: 'input-too-large',
      message: `${file} is ${info.size} bytes, above the maxFileBytes limit of ${limits.maxFileBytes}; it was not read.`,
      suggestion: 'Raise --max-file-bytes, or split the input.',
    })
    return null
  }
  let bytes
  try {
    bytes = await readFile(real)
  } catch (error) {
    sink.add({ file, ruleId: 'input-unreadable', message: `${file} could not be read: ${error.code ?? 'unknown error'}.` })
    return null
  }
  const decoded = decodeUtf8(bytes)
  if (!decoded.ok) {
    sink.add({
      file,
      ruleId: 'input-not-utf8',
      message: `${file} is not valid UTF-8, so it was not parsed. Whether a file decodes is the decoder's decision, never an inference drawn from the decoded text.`,
      suggestion: 'Re-encode the file as UTF-8.',
    })
    return null
  }
  try {
    return { value: JSON.parse(decoded.text) }
  } catch (error) {
    sink.add({
      file,
      ruleId: 'input-not-json',
      message: `${file} is not valid JSON: ${parseFailureDetail(error)}`,
      suggestion: 'Validate the file with a JSON parser before re-running.',
    })
    return null
  }
}

function emptyState(files) {
  return {
    files,
    counts: { endpoints: 0, redirectUris: 0, postLogoutUris: 0, keys: 0, usableKeys: 0, settings: 0 },
    profile: {
      issuer: null,
      expectedIssuer: null,
      issuerMatches: null,
      redirectUris: [],
      postLogoutUris: [],
      signingKeys: [],
      algorithms: { selected: null, offered: [], permitted: [] },
    },
    incomplete: false,
  }
}

const COMPILERS = Object.freeze({
  client: compileClient,
  jwks: compileJwks,
  metadata: compileMetadata,
  policy: compilePolicy,
})

/**
 * Check a discovery document, a client's settings and a key set against a
 * policy.
 *
 * @param {object} options
 * @param {string} options.root Directory holding the four documents.
 * @param {string} [options.metadata] Discovery metadata, relative to the root.
 * @param {string} [options.client] Client settings, relative to the root.
 * @param {string} [options.jwks] Key set, relative to the root.
 * @param {string} [options.policy] Policy, relative to the root.
 * @param {object} [options.limits] Limit overrides; an unknown key throws.
 * @param {Function} [options.clock] Monotonic millisecond source for the time
 *   budget. Injected so a test can drive the budget without waiting, and so
 *   that nothing in this package reads a wall clock.
 * @returns {Promise<object>} the report.
 */
export async function checkOidcConfiguration(options = {}) {
  if (!isPlainObject(options)) throw new TypeError('options must be an object')
  for (const key of Object.keys(options).sort(byCodeUnit)) {
    if (!ALLOWED_OPTIONS.includes(key)) {
      throw new TypeError(`Unknown option "${excerpt(key, 60)}"; known options are ${ALLOWED_OPTIONS.join(', ')}`)
    }
  }
  const limits = validateLimits(options.limits ?? {})
  if (typeof options.root !== 'string' || options.root.length === 0) throw new TypeError('root must be a non-empty string')
  if (options.clock !== undefined && typeof options.clock !== 'function') throw new TypeError('clock must be a function returning milliseconds')

  const names = {
    client: validateName(options.client ?? DEFAULT_CLIENT_NAME, '--client'),
    jwks: validateName(options.jwks ?? DEFAULT_JWKS_NAME, '--jwks'),
    metadata: validateName(options.metadata ?? DEFAULT_METADATA_NAME, '--metadata'),
    policy: validateName(options.policy ?? DEFAULT_POLICY_NAME, '--policy'),
  }

  let realRoot
  try {
    realRoot = await realpath(options.root)
  } catch (error) {
    throw new Error(`--root could not be resolved: ${error.code ?? 'unknown error'}`)
  }
  let rootInfo
  try {
    rootInfo = await stat(realRoot)
  } catch (error) {
    throw new Error(`--root could not be inspected: ${error.code ?? 'unknown error'}`)
  }
  if (!rootInfo.isDirectory()) throw new Error('--root must be a directory')

  const clock = options.clock ?? (() => performance.now())
  const started = clock()
  const budget = {
    check() {
      if (clock() - started > limits.maxRuntimeMs) throw new TimeBudgetExceeded()
    },
  }

  const sink = new FindingSink()
  const state = emptyState(names)

  const parsed = {}
  for (const kind of INPUTS) {
    const name = names[kind]
    const located = await resolveInput(realRoot, name)
    if (!located.ok) {
      // (1) An input that could not be reached is missing evidence, not a
      // verdict about it.
      state.incomplete = true
      if (located.reason === 'escapes') {
        sink.add({
          file: name,
          ruleId: 'path-escapes-root',
          message: `${name} resolves outside --root, so it was refused unread.`,
          suggestion: 'Keep all four documents inside the declared root; a symbolic link out of the tree is refused.',
        })
      } else {
        sink.add({
          file: name,
          ruleId: 'input-unreadable',
          message: `${name} could not be resolved inside --root: ${located.code ?? 'unknown error'}.`,
          suggestion: 'Check the file name and its permissions.',
        })
      }
      parsed[kind] = null
      continue
    }
    const loaded = await loadJson(sink, name, located.real, limits)
    // (2) Unreadable, undecodable or unparseable bytes are missing evidence too.
    if (loaded === null) state.incomplete = true
    parsed[kind] = loaded
  }

  const compiled = {}
  for (const kind of INPUTS) {
    if (parsed[kind] === null) {
      compiled[kind] = null
      continue
    }
    const document = COMPILERS[kind](sink, names[kind], parsed[kind].value, limits)
    // (3) A document whose shape, version or size this build cannot take is a
    // document nothing was learned from.
    if (document === null) state.incomplete = true
    compiled[kind] = document
  }

  for (const kind of INPUTS) {
    const document = compiled[kind]
    if (document === null) continue
    // (4) A member, entry or list that did not compile was not compared against
    // anything. Reporting `fail` here would claim the whole document was read
    // when part of it was refused.
    if (document.refused > 0) state.incomplete = true
  }

  if (INPUTS.every((kind) => compiled[kind] !== null)) {
    try {
      const outcome = runChecks(sink, names, compiled, budget)
      state.counts = outcome.counts
      state.profile = outcome.profile
      // (5) An algorithm, key type or redirect URI this build could not reason
      // about leaves its subject unchecked, and an unchecked subject is never
      // reported as satisfied.
      if (outcome.incomplete) state.incomplete = true

      /**
       * (6) The vacuous pass, refused explicitly.
       *
       * Four documents that all compile, with nothing left to check -- no
       * endpoint, no redirect URI, no key, no setting -- would otherwise report
       * `pass` with `checked: 0`, which is green on no evidence at all. This is
       * the only thing standing between that input and a green build, so it is
       * an error, it marks the run incomplete, and `test/incomplete.test.mjs`
       * fails if either half is removed.
       *
       * It is confined to runs that reached the checks: a run whose documents
       * could not be read has already said so under its own rule, and repeating
       * it here would backstop those flags, so removing one of them would
       * change nothing observable and no test could catch it.
       */
      const counts = state.counts
      if (counts.endpoints + counts.redirectUris + counts.postLogoutUris + counts.keys + counts.settings === 0) {
        state.incomplete = true
        sink.add({
          file: names.client,
          ruleId: 'no-checks-performed',
          message: 'The four documents were read and there was nothing in them to check: no endpoint, no redirect URI, no key and no client setting. A report with nothing checked has no evidence to be green on.',
          suggestion: 'Check that these are the documents you meant to point at.',
        })
      }
    } catch (error) {
      if (!(error instanceof TimeBudgetExceeded)) throw error
      // (7) A run that stopped early checked less than it was asked to, and the
      // phase it stopped inside contributed nothing to the profile.
      state.incomplete = true
      sink.add({
        file: names.jwks,
        ruleId: 'time-budget-exceeded',
        message: `The check passed the maxRuntimeMs budget of ${limits.maxRuntimeMs} and stopped; whatever the interrupted phase would have reported is absent from this report rather than partly present.`,
        suggestion: 'Raise --max-runtime-ms, or split the inputs.',
      })
    }
  }

  return buildReport(sink, state, limits)
}

/** stdout carries this and nothing else, so it can be piped straight into a parser. */
export function serializeReport(report) {
  return JSON.stringify(report, null, 2)
}

/** 0 completed and passed, 1 completed and failed, 2 the run could not be completed. */
export function exitCodeFor(report) {
  if (report.status === 'incomplete') return 2
  return report.status === 'fail' ? 1 : 0
}

const SEVERITY_WIDTH = 7

/** The human summary. It goes to stderr; stdout is the JSON report alone. */
export function formatReport(report) {
  const { summary, profile } = report
  const matches = profile.issuerMatches === null ? 'not compared' : profile.issuerMatches ? 'matches the client' : 'does not match the client'
  const lines = [
    `issuer ${profile.issuer === null ? '(not read)' : profile.issuer}: ${matches}.`,
    `redirect ${summary.redirectUris} URI(s) and ${summary.postLogoutUris} post-logout URI(s) compared exactly against the policy.`,
    `keys ${summary.usableKeys} of ${summary.keys} usable for rotation; algorithm ${profile.algorithms.selected ?? '(not read)'}.`,
    `${summary.checked} subject(s) checked: ${summary.errors} error, ${summary.warnings} warning, status ${report.status}.`,
  ]
  for (const finding of report.findings) {
    lines.push(
      `${finding.severity.toUpperCase().padEnd(SEVERITY_WIDTH)} ` +
      `${finding.location.file}${finding.location.pointer} ${finding.ruleId} ${finding.message}`,
    )
  }
  return `${lines.join('\n')}\n`
}

export { EXACT_MATCHING, REQUIRED_PKCE_METHOD, runChecks } from './checks.mjs'
export {
  ALGORITHMS, KEY_TYPES, KEY_USES, KNOWN_KEY_MEMBERS, NONE_ALGORITHM, PRIVATE_PARAMETERS,
  bitLengthOf, byteLengthOf, classifyAlgorithm, coordinateBytesFor, inspectKeyMaterial,
  privateParametersIn,
} from './algorithms.mjs'
export {
  CLIENT_KEYS, CLIENT_REQUIRED, DOCUMENT_SCHEMA_VERSION, JWKS_KEYS, KNOWN_METADATA_KEYS,
  METADATA_ENDPOINT_KEYS, POLICY_KEYS, POLICY_REQUIRED, REQUIRED_METADATA_KEYS,
  compileClient, compileJwks, compileMetadata, compilePolicy,
} from './documents.mjs'
export {
  EXCERPT_LIMIT, MAX_DESCRIPTION_LENGTH, MAX_IDENTIFIER_LENGTH, MAX_URI_LENGTH, byCodeUnit,
  decodeUtf8, describeValue, excerpt, hasForbiddenCharacter, isBase64Url, isIdentifier,
  isPlainObject, isResponseType, isToken, parseFailureDetail,
} from './text.mjs'
export { inspectEndpoint, inspectRedirectUri } from './uri.mjs'
