# oidc-configuration-checker

Check exported OpenID Connect **discovery metadata**, **relying-party settings**
and a published **JWKS** against an issuer, redirect and key-rotation policy.

It reads four local files and nothing else. It never contacts an issuer, never
requests or reads a token, never performs any part of an authorization flow, and
opens no socket at all — [proved, not asserted](#what-a-pass-means).

- **Repository:** [edilec/oidc-configuration-checker](https://github.com/edilec/oidc-configuration-checker)
- **Area:** Security & Privacy
- **License:** MIT
- Node >= 22, ESM, **zero dependencies** — runtime and development alike.

## Install and run

```sh
npx oidc-configuration-checker --root ./oidc
```

`--root` holds four files. Their names default to `metadata.json`,
`client.json`, `jwks.json` and `policy.json` and can each be given explicitly
with `--metadata`, `--client`, `--jwks` and `--policy`.

```sh
oidc-configuration-checker --root ./oidc --json | jq '.profile.signingKeys[] | select(.status != "usable")'
```

`stdout` carries the JSON report and nothing else, so it pipes straight into a
parser. `stderr` carries the human summary and the diagnostics — **a non-empty
stderr is correct**, not an error.

## Input

Two of the four files are **exports you already have**, saved verbatim:

```json
// metadata.json — what the provider publishes at its discovery endpoint
{
  "issuer": "https://id.example.invalid",
  "authorization_endpoint": "https://id.example.invalid/authorize",
  "token_endpoint": "https://id.example.invalid/token",
  "jwks_uri": "https://id.example.invalid/jwks",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256", "RS256"],
  "code_challenge_methods_supported": ["S256"]
}

// jwks.json — the key set the provider publishes
{ "keys": [
  { "kty": "RSA", "use": "sig", "kid": "2026-03-signing", "alg": "RS256", "n": "…", "e": "AQAB" },
  { "kty": "RSA", "use": "sig", "kid": "2025-09-signing", "alg": "RS256", "n": "…", "e": "AQAB" }
] }
```

Two are **documents this tool defines**:

```json
// client.json — what this relying party is configured to do
{
  "schemaVersion": "1",
  "clientId": "storefront-web",
  "expectedIssuer": "https://id.example.invalid",
  "redirectUris": ["https://app.example.invalid/auth/callback"],
  "responseTypes": ["code"],
  "idTokenSignedResponseAlg": "RS256",
  "tokenEndpointAuthMethod": "private_key_jwt",
  "pkceMethod": "S256"
}

// policy.json — what this deployment permits
{
  "schemaVersion": "1",
  "redirectUriMatching": "exact",
  "allowedRedirectUris": ["https://app.example.invalid/auth/callback"],
  "allowedPostLogoutRedirectUris": [],
  "allowedIdTokenSigningAlgs": ["ES256", "RS256"],
  "allowedResponseTypes": ["code"],
  "allowedTokenEndpointAuthMethods": ["private_key_jwt"],
  "requirePkceS256": true,
  "minimumKeys": 2,
  "minRsaModulusBits": 2048
}
```

An unknown key in `client.json`, `policy.json` or at the top level of
`jwks.json` **refuses the document**, so a one-character typo cannot silently
disable a check and no field named `clientSecret` can be read in by accident. An
unknown member of the *discovery document* or of a *JWK* is reported and the
document is still read, because both are extensible by specification and
refusing them would reject every real provider.

## What it checks

**Issuer.** The issuer the metadata declares against the issuer the client
expects, compared byte for byte as OpenID Connect Core requires of the `iss`
claim. A client pointed at one provider while trusting another will accept an ID
token that was never about it — the confused-deputy setup. A difference of
exactly one trailing slash gets its own rule.

**Redirect URIs.** Every registered URI against the policy allowlist, as one
exact string against another. No prefix, no wildcard, no normalisation, no case
folding, anywhere in the package. Prefix matching is how an authorization
response ends up delivered to a host nobody registered, so a `*` is refused
rather than expanded and the run becomes `incomplete`. Fragments, userinfo
components and non-loopback `http` are each their own rule; RFC 8252 loopback
and private-use schemes are accepted, because a check that rejects legitimate
configuration is a defect too.
Issuer and redirect identities carrying a default-ignorable Unicode mark are
refused as incomplete evidence: the raw value can differ while appearing
unchanged in a report. The mark is not echoed in JSON or human output.

**Algorithms.** `none` is refused wherever it appears — offered by the provider,
selected by the client, or permitted by the policy. **A policy that permits
`none` is itself a finding.** An algorithm this build does not implement is
reported as *unsupported*, which is neither permitted nor refused: the run is
`incomplete` and nothing treats it as checked.

**Keys and rotation.** Every key must carry a unique `kid`, or a rotation cannot
select one. Every key must declare an `alg` the policy permits and a key type
this build can inspect. RSA moduli are *measured* from the encoded value with
leading zero bytes stripped, so a short key padded to look long is still
reported short; EC coordinates are measured against their curve. A published
private or symmetric parameter is a finding whose value is never decoded,
measured or echoed. `minimumKeys` says how many usable keys a rotation needs.

## Output

```json
{
  "schemaVersion": "1",
  "tool": "oidc-configuration-checker",
  "status": "fail",
  "summary": { "checked": 15, "errors": 5, "warnings": 0, "endpoints": 5, "redirectUris": 2,
               "postLogoutUris": 1, "keys": 2, "usableKeys": 1, "settings": 5 },
  "profile": {
    "issuer": "https://login.example.invalid",
    "expectedIssuer": "https://id.example.invalid",
    "issuerMatches": false,
    "redirectUris": [{ "uri": "https://app.example.invalid/auth/callback", "status": "allowlisted" }],
    "postLogoutUris": [],
    "signingKeys": [{ "kid": null, "kty": "RSA", "alg": "RS256", "status": "refused" }],
    "algorithms": { "selected": "RS256", "offered": ["RS256", "none"], "permitted": ["ES256", "RS256"] }
  },
  "findings": [ { "ruleId": "issuer-mismatch", "severity": "error", "message": "…",
                  "location": { "file": "client.json", "pointer": "/expectedIssuer" } } ]
}
```

`issuerMatches` is `true`, `false` or `null` — and `null` means *not compared*,
never *fine*. A key's `status` is `usable`, `not-permitted`, `encryption`,
`refused` or `unknown`, and only `usable` counts toward a rotation.
Long redirect URIs are displayed as bounded excerpts. Their profile rows also
carry `rawSha256`, a SHA-256 digest of the exact UTF-16 code units compared,
encoded as UTF-16LE. This identifies distinct long values whose excerpts look
the same; it is not a credential or a live-provider check. When two rendered
URI excerpts collide, the findings name the first differing raw UTF-16 offset
and units without echoing the omitted URI text.
If an entry in either redirect list cannot be evaluated, the run is incomplete.
Known exact matches stay `allowlisted`, but unmatched rows are `unknown` and
the tool makes no `not-allowlisted` or `unused` claim from a partial list.

| Exit | Status | Meaning |
| ---: | --- | --- |
| 0 | `pass` | The four documents were checked and no error-severity rule fired. |
| 1 | `fail` | The four documents were checked and at least one error-severity rule fired. |
| 2 | `incomplete` | Evidence was missing, unsupported or truncated. |
| 2 | *(no report)* | Invalid configuration. **stdout is empty** — the run never had a subject. |

A refused value is described, never reproduced, and that holds for a whole
document as well as for a field: an input that will not parse is reported by
position, line and column (`client.json is not valid JSON: Expected
double-quoted property name in JSON at position 37 (line 1 column 38)`). V8's
own parse error quotes the document it choked on, so a file short enough to be
only a client secret would otherwise be reproduced in full in the report. When
V8 answers with the quoting shape it supplies no position of its own, and the
report then names the offending token and whether the failure was reached at
the start of the document or inside it — never a location invented for it, and
never the text at one.

The rule catalog, the limits and the supported dialect are in
[`docs/oidc-rules.md`](./docs/oidc-rules.md).

## Examples

| Directory | Result |
| --- | --- |
| `examples/clean` | exits 0 — nothing to report |
| `examples/broken` | exits 1 — an issuer mismatch, a key with no id, an offered `none`, an unlisted redirect URI |
| `examples/incomplete` | exits 2 — an algorithm this build does not implement, a key with no `alg`, a wildcard in the allowlist |

```sh
npm run example            # examples/clean, exits 0
node bin/oidc-configuration-checker.mjs --root examples/broken; echo $?      # 1
node bin/oidc-configuration-checker.mjs --root examples/incomplete; echo $?  # 2
```

The example key sets hold real public keys, generated once for this repository
with their private halves discarded. No fixture anywhere in this package carries
a private key, a client secret or any other credential.

## Limits and non-goals

### What a pass means

The four documents are consistent with one another: the issuer the client
expects is the issuer the metadata declares, every registered redirect URI is in
the policy allowlist as an exact string, every declared algorithm is one the
policy permits, `none` appears nowhere, and the key set carries enough
identified, permitted, inspectable keys for a rotation to be staged.

**It is not a statement about the provider, and not a statement about your
deployment.** Nothing was fetched. The metadata and the key set are copies
somebody saved, and they may be out of date, edited, or from a different
environment than the one you are asking about.

A control the saved documents carry no evidence about is never part of a pass.
`token_endpoint_auth_methods_supported` is the case worth naming, because it is
OPTIONAL in OpenID Connect Discovery: when a provider does not publish it, the
client's `tokenEndpointAuthMethod` is left out of the checked count, a finding
says so, and the run is `incomplete`. The specification's default of
`client_secret_basic` is not read as evidence either way — a provider that omits
the member may well accept more, so calling the method *unoffered* would be as
wrong as calling it approved.

### What this tool cannot do, and will not do

It performs no part of an OpenID Connect flow. It does not fetch the discovery
document or the key set, request an authorization code, exchange a code, obtain,
decode or verify a token, introspect, revoke, register a client, or sign anyone
in. **Token acquisition and login bypass are outside its scope**, and the
package contains nothing that could do either: there is no code path that opens
a socket, no cryptographic verification, and no credential is read from any
source. `test/no-network.test.mjs` checks this without opening a test socket: a
module-resolution guard refuses network builtins, global fetch is denied, a
loopback-looking issuer is compared as local data under both guards, and the
shipped source is scanned for network and credential capabilities. These are
offline controls, not a claim about a live provider.

It also cannot tell you:

- **Whether the provider behaves as its metadata claims.** A discovery document
  is a statement of intent. Only the live provider can tell you what it enforces.
- **Whether a key can actually verify a signature.** Structure is checked —
  `kid`, `alg`, key type, curve, modulus length, encoding — but no signature is
  produced or verified, and a well-formed key can still be the wrong key.
- **Whether a secret is strong.** When the client selects `HS*`, the ID token is
  verified with the client secret. This tool never reads a secret, so it says so
  and checks nothing else about that algorithm.
- **Whether your scopes are least-privilege.** That is a different question with
  a different tool; this one does not read scopes at all.
- **Whether an algorithm it does not implement is safe.** `RS256` `RS384`
  `RS512` `PS256` `PS384` `PS512` `ES256` `ES384` `ES512` `ES256K` `EdDSA`
  `HS256` `HS384` `HS512` are implemented. Anything else is reported as
  unsupported and makes the run `incomplete`. **Unsupported is not approved.**
- **Whether a redirect URI is reachable or safe to visit.** It is compared as a
  string. Nothing resolves a host, and nothing opens a URL.
- **Anything about a second client.** One client document is read per run, so an
  allowlisted redirect URI this client does not register is reported as spare
  rather than refused: another client may well need it.

### Deliberate strictness

These refuse configurations that some deployments run on purpose. They are
listed here so the refusal is a choice you can disagree with rather than a
surprise:

- There is no development mode. An `http` issuer or endpoint is an error, always.
- A key with no `alg` is unknown, not permitted, even though RFC 7517 makes the
  member optional.
- A response type is compared as an exact string, so `"code id_token"` and
  `"id_token code"` are different values — because that is how providers match
  them.
- An unknown key in a document this tool defines refuses that document outright.
- A key set with nothing usable in it fails even when the client selected `HS*`
  and needs no key from it. The key set is the provider's, other clients read it,
  and an unusable one is a misconfiguration whoever is looking.

## Development

```sh
npm run check     # lint, test, run the clean example, and pack
```

`npm run lint` is `node --check` over every file. `npm test` is `node --test`.
There are no dependencies to install.

## License

MIT. See [LICENSE](./LICENSE).
