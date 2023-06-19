#!/usr/bin/env node

import process from 'node:process'

import {
  DEFAULT_CLIENT_NAME,
  DEFAULT_JWKS_NAME,
  DEFAULT_METADATA_NAME,
  DEFAULT_POLICY_NAME,
  checkOidcConfiguration,
  excerpt,
  exitCodeFor,
  formatReport,
  serializeReport,
} from '../src/index.mjs'

const VERSION = '0.1.0'

const HELP = `oidc-configuration-checker

Check exported OpenID Connect discovery metadata, relying-party settings and a
published key set against an issuer, redirect and key-rotation policy.

Four local files are the only evidence there is. This tool never contacts an
issuer, never requests or reads a token, never performs an authorization flow
and opens no socket at all.

Usage:
  oidc-configuration-checker --root DIR [--metadata FILE] [--client FILE]
                             [--jwks FILE] [--policy FILE] [--json]
                             [--max-file-bytes N] [--max-keys N]
                             [--max-redirect-uris N] [--max-algorithms N]
                             [--max-list-entries N] [--max-metadata-keys N]
                             [--max-runtime-ms N] [--max-findings N]

Options:
  --root DIR               Directory holding the four documents (required)
  --metadata FILE          Discovery document as the provider publishes it
                           (default ${DEFAULT_METADATA_NAME})
  --client FILE            Relying-party settings (default ${DEFAULT_CLIENT_NAME})
  --jwks FILE              Key set as the provider publishes it
                           (default ${DEFAULT_JWKS_NAME})
  --policy FILE            Issuer, redirect, algorithm and rotation policy
                           (default ${DEFAULT_POLICY_NAME})
  --json                   Suppress the human summary on stderr
  --max-file-bytes N       Maximum bytes per document (default 5242880)
  --max-keys N             Maximum keys in the key set (default 100)
  --max-redirect-uris N    Maximum URIs in one redirect list (default 50)
  --max-algorithms N       Maximum entries in one algorithm list (default 64)
  --max-list-entries N     Maximum entries in any other list (default 32)
  --max-metadata-keys N    Maximum members in the discovery document (default 200)
  --max-runtime-ms N       Time budget for the checks (default 10000)
  --max-findings N         Maximum findings in one report (default 1000)
  -h, --help               Show this help
  -v, --version            Show the version

Every option that carries a value may be given only once: a repeated flag is a
configuration error, not a silent last-wins.

Output:
  stdout  the JSON report only, so it can be piped straight into a parser
  stderr  the human summary and diagnostics

What a pass means:
  The four documents agree with one another: the issuer the client expects is
  the issuer the metadata declares, every redirect URI the client registers is
  in the policy allowlist as an exact string, every declared algorithm is one
  the policy permits, "none" appears nowhere, and the key set carries enough
  usable keys, each with a key id, for a rotation to be staged.

  It is not a statement about the provider. Nothing here was fetched, no token
  was obtained and no flow was attempted, so a pass says the recorded
  configuration is consistent with the recorded policy -- never that the running
  deployment matches either.

Exit codes:
  0  the documents were checked and nothing contradicted the policy
  1  the documents were checked and at least one error-severity rule fired
  2  invalid configuration (no report on stdout), or evidence that could not be
     obtained (an "incomplete" report on stdout, never a "pass")
`

const LIMIT_FLAGS = new Map([
  ['--max-algorithms', 'maxAlgorithms'],
  ['--max-file-bytes', 'maxFileBytes'],
  ['--max-findings', 'maxFindings'],
  ['--max-keys', 'maxKeys'],
  ['--max-list-entries', 'maxListEntries'],
  ['--max-metadata-keys', 'maxMetadataKeys'],
  ['--max-redirect-uris', 'maxRedirectUris'],
  ['--max-runtime-ms', 'maxRuntimeMs'],
])

const VALUE_FLAGS = new Map([
  ['--client', 'client'],
  ['--jwks', 'jwks'],
  ['--metadata', 'metadata'],
  ['--policy', 'policy'],
  ['--root', 'root'],
])

function parseArguments(argv) {
  if (argv.includes('-h') || argv.includes('--help')) return { help: true }
  if (argv.includes('-v') || argv.includes('--version')) return { version: true }

  const options = { root: null, metadata: null, client: null, jwks: null, policy: null, json: false, limits: {} }
  const given = new Set()

  /**
   * A flag that carries a value is accepted once.
   *
   * Letting it repeat discards the earlier value with no diagnostic, so
   * `--policy strict.json --policy lax.json` checks against a policy nobody
   * named. That is the same defect as an ignored typo, which this tool also
   * refuses.
   */
  const once = (name) => {
    if (given.has(name)) throw new Error(`${name} was given more than once`)
    given.add(name)
  }

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    const takeValue = (name) => {
      const value = argv[index + 1]
      if (value === undefined || value.startsWith('-')) throw new Error(`${name} requires a value`)
      index += 1
      return value
    }

    if (argument === '--json') options.json = true
    else if (VALUE_FLAGS.has(argument)) {
      once(argument)
      options[VALUE_FLAGS.get(argument)] = takeValue(argument)
    } else if (LIMIT_FLAGS.has(argument)) {
      once(argument)
      const raw = takeValue(argument)
      if (!/^\d+$/.test(raw) || Number(raw) < 1) throw new Error(`${argument} requires a positive integer`)
      options.limits[LIMIT_FLAGS.get(argument)] = Number(raw)
    // argv is the one untrusted string that reaches a stream without passing
    // through a finding, so it is flattened exactly as a finding would be.
    } else throw new Error(`Unknown option "${excerpt(argument, 60)}"`)
  }

  if (options.root === null) throw new Error('--root is required')
  return options
}

async function main(argv) {
  let options
  try {
    options = parseArguments(argv)
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${HELP}`)
    return 2
  }
  if (options.help) {
    process.stdout.write(HELP)
    return 0
  }
  if (options.version) {
    process.stdout.write(`${VERSION}\n`)
    return 0
  }

  let report
  try {
    report = await checkOidcConfiguration({
      root: options.root,
      limits: options.limits,
      ...(options.metadata === null ? {} : { metadata: options.metadata }),
      ...(options.client === null ? {} : { client: options.client }),
      ...(options.jwks === null ? {} : { jwks: options.jwks }),
      ...(options.policy === null ? {} : { policy: options.policy }),
    })
  } catch (error) {
    // A configuration error never had a subject, so stdout stays empty and the
    // consumer that pipes stdout gets nothing rather than a fabricated report.
    process.stderr.write(`${excerpt(error.message, 400)}\n`)
    return 2
  }

  process.stdout.write(`${serializeReport(report)}\n`)
  if (!options.json) process.stderr.write(formatReport(report))
  if (report.status === 'incomplete') {
    process.stderr.write(
      `incomplete: evidence was missing, unsupported or truncated; ${report.summary.checked} subject(s) were checked and this run is not a pass.\n`,
    )
  }
  return exitCodeFor(report)
}

process.exitCode = await main(process.argv.slice(2))
