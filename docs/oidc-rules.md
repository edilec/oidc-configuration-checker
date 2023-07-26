# Rule catalog, limits and the supported dialect

`oidc-configuration-checker` reads four local documents and reports what they
say about one another. It contacts no issuer, requests no token, reads no token
and performs no authorization flow. Everything below is a statement about those
four documents and nothing else.

## Input dialect

Two of the four files are **exports**. You already have them, and this tool
reads the copy you saved rather than going and getting it:

- `metadata.json` — the discovery document a provider publishes at
  `/.well-known/openid-configuration`, saved verbatim.
- `jwks.json` — the key set the provider publishes, saved verbatim.

Two are **documents this tool defines**, and they carry `"schemaVersion": "1"`:

- `client.json` — what this relying party is configured to do.
- `policy.json` — what this deployment permits.

```json
// client.json
{
  "schemaVersion": "1",
  "clientId": "storefront-web",
  "expectedIssuer": "https://id.example.invalid",
  "redirectUris": ["https://app.example.invalid/auth/callback"],
  "postLogoutRedirectUris": ["https://app.example.invalid/signed-out"],
  "responseTypes": ["code"],
  "idTokenSignedResponseAlg": "RS256",
  "tokenEndpointAuthMethod": "private_key_jwt",
  "pkceMethod": "S256",
  "description": "Public web front end."
}

// policy.json
{
  "schemaVersion": "1",
  "redirectUriMatching": "exact",
  "allowedRedirectUris": ["https://app.example.invalid/auth/callback"],
  "allowedPostLogoutRedirectUris": ["https://app.example.invalid/signed-out"],
  "allowedIdTokenSigningAlgs": ["ES256", "RS256"],
  "allowedResponseTypes": ["code"],
  "allowedTokenEndpointAuthMethods": ["private_key_jwt"],
  "requirePkceS256": true,
  "minimumKeys": 2,
  "minRsaModulusBits": 2048,
  "description": "Storefront relying-party policy."
}
```

`description` is optional in both and is capped at 300 characters. Every other
key above is required; `pkceMethod` and `postLogoutRedirectUris` are optional in
`client.json`.

### Unknown keys are treated differently on purpose

| Document | An unknown key | Why |
| --- | --- | --- |
| `client.json`, `policy.json` | **refuses the document** (`client-invalid`, `policy-invalid`) | This tool defines these. A one-character typo must not silently disable a check, and a field named `clientSecret` must not be read in by accident. |
| `jwks.json` top level | **refuses the document** (`document-invalid`) | A key set carries `keys`. Private material parked beside it cannot then reach the report. |
| `metadata.json` | **reported, document still read** (`metadata-key-unknown`, info) | OpenID Connect Discovery says a provider may publish additional metadata, and most do. Refusing them would reject every real input. |
| a JWK member | **reported, key still read** (`jwk-member-unknown`, info) | JWK members are extensible for the same reason. |

A false refusal is a defect exactly as much as a false pass, which is what the
right-hand column is about.

### Value shapes

| Value | Shape |
| --- | --- |
| key id, client id | 1–120 characters from `[A-Za-z0-9._:/+=~-]`, starting with a letter or digit |
| algorithm, key type, curve, key use, auth method, code challenge method | 1–64 characters from `[A-Za-z0-9._-]`, starting with a letter or digit |
| response type | one or more of the above separated by single spaces, compared as an **exact string** |
| redirect URI | at most 2048 characters, absolute, no whitespace, no control/bidi character |
| JWK parameter | base64url, at most 1024 characters, length never 1 mod 4 |

Nothing outside those shapes is read. No pattern is ever compiled from input:
every regular expression in this package is a literal, and each runs against a
length this package has already bounded.

## Issuer

The issuer is compared **byte for byte**, as OpenID Connect Core requires of the
`iss` claim. A client that trusts one issuer while reading the discovery
document of another will accept an ID token that was never about it — the
confused-deputy setup this check exists for.

An issuer identifier is an `https` URL with no query and no fragment (OpenID
Connect Discovery 1.0 §2). A difference of exactly one trailing slash gets its
own rule, because it is the mismatch people argue about.

Endpoints declared in the discovery document are checked for `https`, and for
whether they sit on the issuer's origin. **A differing origin is a warning, not
an error**: several large providers legitimately serve their key set from
another host, so an error there would be a false refusal. It is reported because
a tampered discovery document looks exactly like that too.

## Redirect URIs

Every comparison is one exact string against another. No prefix, no wildcard, no
normalisation, no case folding, anywhere in the package. Prefix and pattern
matching is how an authorization response is delivered to a host nobody
registered, and a checker that mirrored the loose behaviour could not detect the
loose behaviour.

Consequences worth stating plainly:

- A trailing slash, a differing host case or a differing percent-encoding is a
  mismatch. Where a case-insensitive comparison *would* have matched, the
  suggestion says so.
- A `*` anywhere in a URI is refused, and the run becomes `incomplete`: coverage
  was then decided against part of a list rather than all of it.

Schemes: `https` always; `http` only for the loopback literals `127.0.0.1` and
`[::1]` (RFC 8252 §8.3), with the `localhost` spelling accepted as a **warning**
because what that name resolves to is not the application's decision; and a
private-use scheme of the form `com.example.app:/callback` (RFC 8252 §7.1),
recognised by the dot that distinguishes it from a bare scheme any other
installed application could also claim.

## Algorithms

`none` is refused in all three places it can appear: offered by the provider,
selected by the client, permitted by the policy. **A policy that permits `none`
is itself a finding**, not a licence.

The algorithms this build implements: `RS256` `RS384` `RS512` `PS256` `PS384`
`PS512` `ES256` `ES384` `ES512` `ES256K` `EdDSA` `HS256` `HS384` `HS512`.

Anything else is **unrecognised**, which is neither permitted nor refused: the
run is `incomplete`, the key or setting is not counted as checked, and nothing
downstream treats it as satisfied. An algorithm this tool does not carry is
unsupported, which is not the same as approved.

`HS*` selected by a client raises a warning and suppresses the "no usable key
for the selected algorithm" check: a symmetric ID token is verified with the
client secret, which this tool never reads, so it has nothing to say about it.

## Keys and rotation

| Property | Rule |
| --- | --- |
| every key carries a `kid` | `jwk-kid-missing` — without one a rotation cannot select a key |
| key ids are unique | `jwk-kid-duplicate` — two keys answering to one id make the selection undefined |
| the algorithm is declared | `jwk-alg-undeclared` — undeclared is unknown, not permitted |
| the algorithm and key type agree | `jwk-alg-key-mismatch`, `jwk-curve-mismatch` |
| the RSA modulus meets the floor | `jwk-rsa-modulus-short` — measured from the encoded modulus with leading zero bytes removed, so a short key padded to look long is still reported short |
| the coordinate fits the curve | `jwk-invalid` |
| nothing private is published | `jwk-private-material` — the parameter names are reported; the values are never decoded, measured or echoed |
| enough usable keys to stage a rotation | `jwks-too-few-keys` against `minimumKeys` |

A key marked `"use": "enc"` is not a signing key; it is recorded as such and is
not a finding.

## Rule catalog

Severity comes from one frozen table in `src/index.mjs`. A rule id is stable
across releases; renaming one is a breaking change and is recorded in the
changelog.

| Rule | Severity | Fires when |
| --- | --- | --- |
| `alg-none-offered` | error | the provider offers `none` as an ID token signing algorithm |
| `alg-none-permitted` | error | the policy permits `none` |
| `alg-none-selected` | error | the client selects `none` |
| `alg-not-offered` | error | the client selects an algorithm the provider does not offer |
| `alg-not-permitted` | error | the client selects an algorithm the policy does not permit |
| `alg-offered-not-permitted` | warning | the provider offers an algorithm the policy does not permit |
| `alg-symmetric-selected` | warning | the client selects `HS*`, which is verified with a secret this tool never reads |
| `alg-unrecognised` | error | a client setting or policy entry names an algorithm this build does not implement |
| `auth-method-not-offered` | error | the client authenticates with a method the provider does not list |
| `auth-method-not-permitted` | error | the client authenticates with a method the policy does not permit |
| `auth-method-support-unknown` | error | the client declares an authentication method and the provider does not publish `token_endpoint_auth_methods_supported`, so it was not checked against the provider at all |
| `client-field-missing` | error | a required member of `client.json` is absent |
| `client-invalid` | error | `client.json` has an unknown key or a member of the wrong shape |
| `document-invalid` | error | `jwks.json` is not a key set this build reads |
| `endpoint-invalid` | error | a declared endpoint is not a URL |
| `endpoint-not-https` | error | a declared endpoint is not `https` |
| `endpoint-origin-differs` | warning | a declared endpoint is served from another origin than the issuer |
| `input-not-json` | error | an input did not parse as JSON. The failure is named by position, line and column; the document itself is never quoted back |
| `input-not-utf8` | error | an input did not decode as UTF-8 |
| `input-too-large` | error | an input is above `maxFileBytes` |
| `input-unreadable` | error | an input could not be reached, inspected or read |
| `issuer-invalid` | error | an issuer is not a URL, or carries a query or fragment |
| `issuer-mismatch` | error | the client expects a different issuer from the one the metadata declares |
| `issuer-not-https` | error | the issuer is not an `https` URL |
| `issuer-trailing-slash` | error | the two issuers differ only by a trailing slash |
| `jwk-alg-key-mismatch` | error | the algorithm needs a different key type than the key declares |
| `jwk-alg-none` | error | a key declares `alg: "none"` |
| `jwk-alg-not-permitted` | error | a key declares an algorithm the policy does not permit |
| `jwk-alg-undeclared` | error | a key declares no `alg` |
| `jwk-alg-unrecognised` | error | a key declares an algorithm this build does not implement |
| `jwk-curve-mismatch` | error | the curve does not carry the declared algorithm |
| `jwk-invalid` | error | a key, or one of its parameters, is not a shape this build reads |
| `jwk-kid-duplicate` | error | two keys declare the same `kid` |
| `jwk-kid-invalid` | error | a `kid` is not a usable identifier |
| `jwk-kid-missing` | error | a key declares no `kid` |
| `jwk-kty-unsupported` | error | a key declares a key type this build does not inspect |
| `jwk-member-unknown` | info | a key declares a member this build does not recognise |
| `jwk-private-material` | error | a published key carries private or symmetric material |
| `jwk-rsa-modulus-short` | error | an RSA modulus is below `minRsaModulusBits` |
| `jwks-no-signing-key` | error | no key in the set is usable for signature verification |
| `jwks-selected-alg-unusable` | error | no usable key carries the algorithm the client selected |
| `jwks-too-few-keys` | error | fewer usable keys than `minimumKeys` |
| `metadata-field-missing` | error | a member a relying party needs is absent from the discovery document |
| `metadata-invalid` | error | a discovery member is not the shape this build reads |
| `metadata-key-unknown` | info | the discovery document declares a member this build does not recognise |
| `no-checks-performed` | error | the four documents read and nothing in them to check |
| `path-escapes-root` | error | an input resolves outside `--root` |
| `pkce-not-s256` | error | the policy requires PKCE with S256 and the client does not use it |
| `pkce-s256-not-offered` | error | the policy requires PKCE with S256 and the provider does not offer it |
| `policy-field-missing` | error | a required member of `policy.json` is absent |
| `policy-invalid` | error | `policy.json` has an unknown key or a member of the wrong shape |
| `redirect-matching-not-exact` | error | the policy declares a matching mode other than `exact` |
| `redirect-uri-duplicate` | error | a redirect URI is listed twice in one list |
| `redirect-uri-fragment` | error | a redirect URI carries a fragment component |
| `redirect-uri-insecure-scheme` | error | a redirect URI is neither `https`, loopback `http`, nor a private-use scheme |
| `redirect-uri-invalid` | error | a redirect URI could not be read |
| `redirect-uri-loopback-hostname` | warning | a loopback redirect URI uses the name `localhost` rather than a literal address |
| `redirect-uri-not-allowlisted` | error | a registered redirect URI is not in the policy allowlist as an exact string |
| `redirect-uri-unused` | info | an allowlisted redirect URI this client does not register |
| `redirect-uri-userinfo` | error | a redirect URI carries a userinfo component |
| `redirect-uri-wildcard` | error | a redirect URI holds a `*` |
| `response-type-not-offered` | error | the client requests a response type the provider does not list |
| `response-type-not-permitted` | error | the client requests a response type the policy does not permit |
| `schema-version-unsupported` | error | `client.json` or `policy.json` declares a schema version this build does not implement |
| `time-budget-exceeded` | error | the run passed `maxRuntimeMs` |
| `too-many-algorithms` | error | an algorithm list is above `maxAlgorithms` |
| `too-many-findings` | error | the report is above `maxFindings` |
| `too-many-keys` | error | the key set is above `maxKeys` |
| `too-many-list-entries` | error | another list, or one key's member count, is above `maxListEntries` |
| `too-many-metadata-keys` | error | the discovery document is above `maxMetadataKeys` |
| `too-many-redirect-uris` | error | a redirect list is above `maxRedirectUris` |

## Limits

| Limit | Default | Cap | Exceeded |
| --- | ---: | ---: | --- |
| `maxFileBytes` | 5242880 | 67108864 | the file is not read |
| `maxKeys` | 100 | 5000 | the key set compiles nothing |
| `maxRedirectUris` | 50 | 2000 | the list is refused whole |
| `maxAlgorithms` | 64 | 512 | the list is refused whole |
| `maxListEntries` | 32 | 512 | the list, or the key, is refused whole |
| `maxMetadataKeys` | 200 | 5000 | the document is not read |
| `maxRuntimeMs` | 10000 | 600000 | the run stops; the interrupted phase reports nothing |
| `maxFindings` | 1000 | 20000 | the report is partial and says so |

Exceeding a limit is never a silent truncation: it produces a finding naming the
limit and the run is `incomplete`. An unknown limit name is a configuration
error, not an ignored key.

## Determinism and ordering

Findings are sorted by `location.file`, then `location.pointer`, then `ruleId`,
then `message`, and every comparison is by UTF-16 code unit. The message is part
of the key because two rules deliberately anchor more than one finding at the
same pointer: an offered algorithm the policy does not permit is a relation
between two documents, so it belongs to the list rather than to one index of it.

Every other ordered value in the report -- the algorithms offered and permitted,
the redirect URIs, the key set -- is ordered the same way. Nothing in this
package reads a clock, a locale, an environment variable or a random source, and
the same four files produce byte-identical stdout every time.

Code-unit ordering is not a detail here. Algorithm names are exactly where it
and locale collation disagree: by code unit `ES256` precedes `EdDSA` and both
precede `none`, while an English collator puts `EdDSA` first and `none` in the
middle. A collated report would list a provider's algorithms differently on a
different machine.

## What makes a run incomplete

Any of these, each with its own finding:

1. An input that could not be reached, read, decoded or parsed.
2. A document whose shape, key set or schema version this build cannot take.
3. A member, entry or list refused for its shape — the rest was compared, so the
   comparison covered less than the documents declare.
4. An algorithm or key type this build does not implement.
5. A redirect URI that could not be read, or that holds a wildcard.
6. A limit reached.
7. The time budget reached.
8. Nothing at all to check — `pass` with `checked: 0` is green on no evidence,
   so it is refused explicitly.

An `incomplete` run exits 2 and its status is never `pass`.

## What this tool does not do

It performs no part of an OpenID Connect flow. It does not fetch the discovery
document, fetch the key set, request an authorization code, exchange a code,
obtain a token, decode a token, verify a signature, introspect, revoke, register
a client, or log anyone in. It holds no credential and reads none: there is no
code path in this package that opens a socket or reads an environment variable,
and `test/no-network.test.mjs` proves both rather than asserting them.

A pass therefore says the four documents are consistent with one another. It is
not evidence about the running deployment, and it is not a security assessment
of the provider.
