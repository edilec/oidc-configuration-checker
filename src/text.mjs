/**
 * Decoding, sanitising, ordering, identifier shapes and URI shapes.
 *
 * Nothing in this module touches the filesystem, the network, the locale or a
 * clock. Every value it handles arrived in a file this tool did not write --
 * a discovery document somebody saved, a JWKS somebody exported -- so every
 * value it returns is treated as data on its way to a report and never as
 * something that may shape a line of output.
 */

/**
 * Order by UTF-16 code unit.
 *
 * Locale-aware comparison -- the string method and the collator class alike --
 * reads ICU data that differs between Node builds and between hosts, and it
 * weighs case and punctuation differently from their code points. The values
 * ordered in this package include algorithm names, and those are exactly where
 * the two disagree: by code unit `EdDSA` follows `ES256` and `none` follows
 * both, while an English collator puts `EdDSA` first and `none` in the middle.
 * A collated report would therefore list a provider's offered algorithms in a
 * different order on a different machine. Every order this package exposes is
 * decided here.
 *
 * Neither spelling of the locale-aware comparison appears anywhere in this
 * package, and `test/ordering.test.mjs` pins what the tool *emits* rather than
 * what its source says -- a scan of the source cannot tell one comparator from
 * the other, so a scan is not the test.
 */
export function byCodeUnit(left, right) {
  if (left === right) return 0
  return left < right ? -1 : 1
}

/**
 * The characters no untrusted value may carry into output, in four classes.
 *
 * Built from code points rather than written literally: a literal U+2028 or
 * U+2029 inside a module is a line terminator to the JavaScript parser, and the
 * rest are invisible in an editor. Spelling each one out keeps this file plain
 * ASCII and keeps the list reviewable.
 *
 * - **C0** (U+0000-U+001F) and **DEL** (U+007F). A newline forges a line in the
 *   human report, ESC opens a terminal escape sequence, NUL truncates a value
 *   in anything that receives it through C.
 * - **C1** (U+0080-U+009F). Easy to forget once C0 is handled, and two of them
 *   need no help: U+0085 NEL is a line break to a great many consumers, and
 *   U+009B is the 8-bit CSI, a terminal control introducer that needs no ESC in
 *   front of it.
 * - **Line and paragraph separators** (U+2028, U+2029).
 * - **Bidi and isolate controls** (U+200E, U+200F, U+202A-U+202E,
 *   U+2066-U+2069). U+202E RIGHT-TO-LEFT OVERRIDE reverses everything printed
 *   after it, so a key id or a redirect host can be displayed as something
 *   other than the value that was compared. Ordinary right-to-left text --
 *   Arabic, Hebrew -- needs none of these: the letters carry their own
 *   direction, so refusing the overrides refuses nothing legitimate.
 */
const DEL_AND_C1 = `${String.fromCharCode(0x7f)}-${String.fromCharCode(0x9f)}`
const SEPARATORS = `${String.fromCharCode(0x2028)}${String.fromCharCode(0x2029)}`
const BIDI =
  `${String.fromCharCode(0x200e)}${String.fromCharCode(0x200f)}` +
  `${String.fromCharCode(0x202a)}-${String.fromCharCode(0x202e)}` +
  `${String.fromCharCode(0x2066)}-${String.fromCharCode(0x2069)}`

/**
 * Stripped from every untrusted string on its way into output -- key ids,
 * client ids, algorithm names, redirect URIs, file names, pointers, messages,
 * suggestions and evidence alike, not only an excerpt field. Tab, newline and
 * carriage return are left out of this class deliberately: `excerpt` collapses
 * them into a single space in the very next step, which is the same result by a
 * shorter route.
 */
const CONTROL = new RegExp(
  `[${String.fromCharCode(0)}-${String.fromCharCode(8)}` +
  `${String.fromCharCode(11)}${String.fromCharCode(12)}` +
  `${String.fromCharCode(14)}-${String.fromCharCode(31)}` +
  `${DEL_AND_C1}${SEPARATORS}${BIDI}]`,
  'g',
)

/**
 * What an identifier or a URI may not contain: the same four classes, plus the
 * three ASCII whitespace controls `CONTROL` leaves to the collapse. A key id
 * that prints differently from the value the rotation check compared is a key
 * nobody can audit, so it is refused at the door rather than cleaned up.
 */
const FORBIDDEN = new RegExp(
  `[${String.fromCharCode(0)}-${String.fromCharCode(31)}` +
  `${DEL_AND_C1}${SEPARATORS}${BIDI}]`,
)

/**
 * Detects any of the four classes anywhere in a string. Exported so tests can
 * walk an entire serialised report and assert that nothing survived anywhere,
 * rather than checking the one field a developer remembered to sanitise.
 */
export function hasForbiddenCharacter(value) {
  return FORBIDDEN.test(String(value))
}

export const EXCERPT_LIMIT = 160
export const MAX_IDENTIFIER_LENGTH = 120
export const MAX_TOKEN_LENGTH = 64
export const MAX_URI_LENGTH = 2048
export const MAX_DESCRIPTION_LENGTH = 300
export const MAX_BASE64URL_LENGTH = 1024

/**
 * A bounded, single-line, control-free rendering of an untrusted string.
 *
 * Every id, file name, pointer, message and piece of evidence that reaches a
 * finding goes through here. A tool in this catalog sanitised its evidence
 * carefully and left its identifiers raw, so a record id holding a newline
 * printed two lines into the human report and invented a finding that was never
 * emitted.
 */
export function excerpt(value, limit = EXCERPT_LIMIT) {
  const flattened = String(value).replace(CONTROL, ' ').replace(/\s+/g, ' ').trim()
  if (flattened.length <= limit) return flattened
  return `${flattened.slice(0, limit)}...`
}

/**
 * The identifier alphabet: key ids and client ids.
 *
 * Wide enough for the spellings real providers use -- a UUID, a base64url
 * thumbprint, a dotted name, a date-stamped rotation label -- which means upper
 * case, `-`, `_` and `=` all occur, which in turn is why ordering in this
 * package is decided by code unit and pinned by what the tool emits.
 */
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/+=~-]*$/

export function isIdentifier(value) {
  if (typeof value !== 'string') return false
  if (value.length === 0 || value.length > MAX_IDENTIFIER_LENGTH) return false
  if (FORBIDDEN.test(value)) return false
  return IDENTIFIER.test(value)
}

/**
 * The token alphabet: algorithm names (`RS256`, `EdDSA`), key types (`RSA`),
 * curves (`P-256`, `secp256k1`), key uses (`sig`) and token endpoint
 * authentication methods (`private_key_jwt`). Narrower than an identifier
 * because every one of these is drawn from a registry, not chosen by a
 * deployment.
 */
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/

export function isToken(value) {
  if (typeof value !== 'string') return false
  if (value.length === 0 || value.length > MAX_TOKEN_LENGTH) return false
  if (FORBIDDEN.test(value)) return false
  return TOKEN.test(value)
}

/**
 * A `response_type` is one or more tokens separated by single spaces, and it is
 * compared as an exact string.
 *
 * OpenID Connect treats the value as a set, so `"code id_token"` and
 * `"id_token code"` request the same thing -- but a provider's
 * `response_types_supported` list carries one spelling and providers match it
 * literally. This tool compares strings and says so, which is why a differently
 * ordered spelling is reported as not offered rather than quietly accepted:
 * the report then matches what the provider will actually do.
 */
const RESPONSE_TYPE = /^[A-Za-z0-9._-]+(?: [A-Za-z0-9._-]+)*$/

export function isResponseType(value) {
  if (typeof value !== 'string') return false
  if (value.length === 0 || value.length > MAX_IDENTIFIER_LENGTH) return false
  if (FORBIDDEN.test(value)) return false
  return RESPONSE_TYPE.test(value)
}

/**
 * base64url, as JWK parameters are encoded.
 *
 * The charset is checked here rather than left to the decoder: `Buffer.from`
 * with `base64url` silently drops anything outside the alphabet, so a parameter
 * holding punctuation would decode to a shorter value and a modulus would be
 * measured as smaller -- or larger -- than it is. A length of 1 mod 4 encodes no
 * whole byte and is refused for the same reason. The input is bounded before
 * the pattern runs; the pattern itself has no alternation and no nested
 * quantifier, so its cost is linear in a length this module has already capped.
 */
const BASE64URL = /^[A-Za-z0-9_-]+$/

export function isBase64Url(value) {
  if (typeof value !== 'string') return false
  if (value.length === 0 || value.length > MAX_BASE64URL_LENGTH) return false
  if (value.length % 4 === 1) return false
  return BASE64URL.test(value)
}

/**
 * Say what a refused value was, without reproducing any of it.
 *
 * A rejected field is arbitrary content from a file this tool did not write,
 * and the report goes to stdout -- a stream that is piped, logged and pasted
 * somewhere more public than the input ever was. Echoing the value back hands
 * that content a wider audience than it had, on exactly the fields whose
 * validation exists to keep something unexpected out of the report. The pointer
 * on the finding names the exact position in the file, which is all a reader
 * needs; the value stays in the file, where it started.
 *
 * This matters more here than in most of the catalog: the files this tool reads
 * sit next to the files that hold client secrets, and a private key parameter
 * that reached the report would be published by the next CI job that archives
 * it.
 */
export function describeValue(value) {
  if (value === undefined) return 'nothing'
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') return Number.isInteger(value) ? 'an integer' : 'a number'
  if (typeof value === 'string') return `a string of ${value.length} character(s)`
  if (Array.isArray(value)) return `an array of ${value.length} item(s)`
  if (typeof value === 'object') return 'an object'
  return `a ${typeof value}`
}

/**
 * Decode bytes as UTF-8, strictly.
 *
 * `fatal: true` is the whole point. Decoding leniently and then hunting for
 * U+FFFD cannot tell undecodable bytes from a file that legitimately contains a
 * replacement character, and that confusion has already let an unread input
 * report a pass in this catalog. The decoder decides; the decoded text never
 * gets a vote. Every file this tool opens goes through here -- the policy
 * document included, because that is precisely where a sibling tool hardened
 * its data path and forgot its own configuration.
 */
export function decodeUtf8(bytes) {
  try {
    return { ok: true, text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes) }
  } catch {
    return { ok: false, reason: 'not-utf8' }
  }
}

/** True for a plain object -- not an array, not null, not a class instance dressed up as one. */
export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}
