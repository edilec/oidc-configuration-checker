/**
 * The algorithm registry this build implements, and the structural inspection
 * of one JWK.
 *
 * The registry is a closed list on purpose. An algorithm name this build does
 * not carry is **unsupported**, which is not the same as approved and not the
 * same as refused: the tool says it does not know, the run is incomplete, and
 * nothing downstream treats the key or the client setting as checked. A
 * checker that shrugged at an unfamiliar `alg` and moved on would be reporting
 * "verified" about evidence it never obtained, which is the one failure mode
 * this catalog treats as worse than no tool at all.
 *
 * Nothing here performs cryptography. No signature is produced or verified, no
 * key is imported, and no private material is ever decoded: the only arithmetic
 * is counting the bits of a public modulus, which is a property of the
 * configuration rather than an operation on a key.
 */

import { Buffer } from 'node:buffer'

import { MAX_BASE64URL_LENGTH, byCodeUnit, isBase64Url } from './text.mjs'

/**
 * `none` is not in the registry below and never will be.
 *
 * An `alg` of `none` means an unsigned JWT. A provider that offers it, a client
 * that selects it and a policy that permits it are three different mistakes and
 * each gets its own rule; none of them is a configuration this tool will call
 * satisfied, whatever the policy document says. This constant exists so that
 * the refusal is written once and can be found from every site that needs it.
 */
export const NONE_ALGORITHM = 'none'

/**
 * JWS signature algorithms this build implements, with the key each one needs.
 *
 * `kty` and `curves` are what a JWKS entry must declare for a key to be usable
 * with that algorithm: an `ES256` key on `P-384` is a configuration that cannot
 * verify anything, and providers do publish that pairing by accident when a
 * curve is changed and the `alg` label is not.
 */
export const ALGORITHMS = Object.freeze({
  EdDSA: { kty: 'OKP', curves: ['Ed25519', 'Ed448'], symmetric: false },
  ES256: { kty: 'EC', curves: ['P-256'], symmetric: false },
  ES256K: { kty: 'EC', curves: ['secp256k1'], symmetric: false },
  ES384: { kty: 'EC', curves: ['P-384'], symmetric: false },
  ES512: { kty: 'EC', curves: ['P-521'], symmetric: false },
  HS256: { kty: 'oct', curves: null, symmetric: true },
  HS384: { kty: 'oct', curves: null, symmetric: true },
  HS512: { kty: 'oct', curves: null, symmetric: true },
  PS256: { kty: 'RSA', curves: null, symmetric: false },
  PS384: { kty: 'RSA', curves: null, symmetric: false },
  PS512: { kty: 'RSA', curves: null, symmetric: false },
  RS256: { kty: 'RSA', curves: null, symmetric: false },
  RS384: { kty: 'RSA', curves: null, symmetric: false },
  RS512: { kty: 'RSA', curves: null, symmetric: false },
})

/** Key types this build can inspect. Anything else is unsupported, not refused. */
export const KEY_TYPES = Object.freeze(['EC', 'OKP', 'RSA', 'oct'])

/** Expected length in bytes of a curve coordinate, used to catch a mislabelled key. */
const CURVE_COORDINATE_BYTES = Object.freeze({
  Ed25519: 32,
  Ed448: 57,
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  secp256k1: 32,
})

/**
 * Every JWK member that carries private or symmetric key material, under every
 * key type at once.
 *
 * Checked regardless of what the key says its `kty` is: a key labelled `RSA`
 * that carries a `k` is either mislabelled or is hiding a shared secret in a
 * document meant to be published, and both readings are worth a finding. The
 * names are matched; the values are never decoded, never measured and never
 * reported.
 */
export const PRIVATE_PARAMETERS = Object.freeze(['d', 'dp', 'dq', 'k', 'oth', 'p', 'q', 'qi'])

/** Public JWK members this build recognises. Anything else is reported, not read. */
export const KNOWN_KEY_MEMBERS = Object.freeze([
  'alg', 'crv', 'e', 'key_ops', 'kid', 'kty', 'n', 'use', 'x', 'x5c', 'x5t', 'x5t#S256', 'x5u', 'y',
])

/** Values `use` may take, from RFC 7517. */
export const KEY_USES = Object.freeze(['enc', 'sig'])

/**
 * Classify an algorithm name.
 *
 * Three outcomes, and the difference between the second and the third is the
 * difference between a verdict and an admission:
 *
 * - `none`: refused, always, whatever any document says.
 * - a name in the registry: implemented, and the caller may check it against
 *   the policy.
 * - anything else: **unrecognised**. The caller reports it as unsupported and
 *   the run becomes incomplete. It is never compared against the policy list,
 *   because a name this build cannot reason about could be anything -- a strong
 *   algorithm, a vendor extension, or a typo for one this build would refuse.
 */
export function classifyAlgorithm(name) {
  if (name === NONE_ALGORITHM) return { kind: 'none' }
  if (typeof name === 'string' && Object.hasOwn(ALGORITHMS, name)) {
    return { kind: 'known', name, ...ALGORITHMS[name] }
  }
  return { kind: 'unrecognised' }
}

/**
 * The bit length of a base64url-encoded big-endian integer, or `null` when the
 * value is not something this build can measure.
 *
 * Leading zero bytes are stripped before counting, because a 2048-bit modulus
 * padded to 257 bytes is still a 2048-bit modulus and a 1024-bit modulus padded
 * to 256 bytes is still a 1024-bit modulus. Measuring the encoded length alone
 * would call the second one 2048 and hand a weak key a pass.
 */
export function bitLengthOf(encoded) {
  if (!isBase64Url(encoded)) return null
  const bytes = Buffer.from(encoded, 'base64url')
  if (bytes.length === 0) return null
  let index = 0
  while (index < bytes.length && bytes[index] === 0) index += 1
  if (index === bytes.length) return 0
  let bits = (bytes.length - index - 1) * 8
  for (let octet = bytes[index]; octet > 0; octet >>= 1) bits += 1
  return bits
}

/** Decoded byte length of a base64url value, or `null` when it is not measurable. */
export function byteLengthOf(encoded) {
  if (!isBase64Url(encoded)) return null
  return Buffer.from(encoded, 'base64url').length
}

/**
 * Inspect the material of one JWK: which parameters are present, whether they
 * are encoded as this build requires, and how large the RSA modulus is.
 *
 * Returns a list of problems rather than findings. `checks.mjs` decides what a
 * problem means; this function decides only what is there. Every returned
 * problem names a parameter and a reason, and never carries the value: the
 * caller has no way to echo what it was not given.
 */
export function inspectKeyMaterial(entry, kty) {
  const problems = []
  let modulusBits = null
  let coordinateBytes = null

  const required = kty === 'RSA' ? ['n', 'e'] : kty === 'EC' ? ['x', 'y'] : kty === 'OKP' ? ['x'] : []

  for (const parameter of required) {
    const value = entry[parameter]
    if (value === undefined) {
      problems.push({ parameter, reason: 'missing' })
      continue
    }
    if (typeof value !== 'string') {
      problems.push({ parameter, reason: 'not-a-string' })
      continue
    }
    if (value.length > MAX_BASE64URL_LENGTH) {
      problems.push({ parameter, reason: 'too-long' })
      continue
    }
    if (!isBase64Url(value)) problems.push({ parameter, reason: 'not-base64url' })
  }

  if (kty === 'RSA' && problems.length === 0) {
    modulusBits = bitLengthOf(entry.n)
    if (modulusBits === null) problems.push({ parameter: 'n', reason: 'not-measurable' })
  }
  if ((kty === 'EC' || kty === 'OKP') && problems.length === 0) {
    coordinateBytes = byteLengthOf(entry.x)
    if (coordinateBytes === null) problems.push({ parameter: 'x', reason: 'not-measurable' })
  }

  return { problems, modulusBits, coordinateBytes }
}

/**
 * Expected coordinate size for a curve, or `null` for a curve this build does
 * not carry a size for. `null` is checked by the caller and leaves the size
 * question unanswered rather than answered wrongly.
 */
export function coordinateBytesFor(curve) {
  return Object.hasOwn(CURVE_COORDINATE_BYTES, curve) ? CURVE_COORDINATE_BYTES[curve] : null
}

/** Every private or symmetric parameter present on a key, ordered by code unit. */
export function privateParametersIn(entry) {
  return PRIVATE_PARAMETERS.filter((parameter) => Object.hasOwn(entry, parameter)).sort(byCodeUnit)
}
