# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Rule ids are
part of the public surface: renaming one is a breaking change and is recorded
here.

## [Unreleased]

### Added

- First implementation of `oidc-configuration-checker`: reads exported OpenID
  Connect discovery metadata, a relying party's settings and a published key
  set, and checks all three against an issuer, redirect and key-rotation policy.
- Issuer alignment compared byte for byte, with a difference of one trailing
  slash reported under its own rule, and declared endpoints checked for
  transport and origin.
- Exact redirect matching: one string against another, with no prefix, wildcard,
  normalisation or case folding anywhere in the package. A wildcard is refused
  rather than expanded and makes the run `incomplete`. RFC 8252 loopback and
  private-use redirect URIs are accepted, so the check does not refuse
  legitimate native-application configuration.
- An algorithm registry that is a closed list. `none` is refused wherever it
  appears — offered, selected, or permitted by the policy — and an algorithm
  this build does not implement is reported as unsupported rather than as
  approved or refused.
- Key-set checks for rotation readiness: a unique `kid` on every key, a declared
  and permitted algorithm, a key type and curve this build can inspect, an RSA
  modulus measured with leading zero bytes stripped, EC coordinates measured
  against their curve, and a `minimumKeys` floor. A published private or
  symmetric parameter is reported by name and its value is never decoded,
  measured or echoed.
- A 71-rule catalog with one frozen `ruleId -> severity` table, documented in
  `docs/oidc-rules.md` and pinned behaviourally by exit code, error count and
  printed severity word.
- `auth-method-support-unknown`, for the one discovery list the settings checks
  compare against that is OPTIONAL in the specification. A provider that does
  not publish `token_endpoint_auth_methods_supported` leaves the client's
  authentication method unchecked against the provider; that setting is now left
  out of the checked count and the run is `incomplete`, where it previously
  skipped the comparison in silence, kept the setting counted and reported
  `pass` on a control it had never checked. The specification's default of
  `client_secret_basic` is deliberately not read as evidence: a provider that
  omits the member may accept more, so reporting `auth-method-not-offered`
  would be a false failure rather than a fix.
- Enforced limits on bytes, keys, redirect URIs, algorithm lists, other lists,
  discovery members, findings and runtime, each reported by name when reached
  and each making the run `incomplete` rather than truncating silently.
- A CLI with `--help`, `--json`, explicit input paths and the three documented
  exit codes; the JSON report on stdout alone.
- Examples for a clean, a failing and an incomplete configuration.

### Security

- No network access of any kind: nothing is fetched, no token is requested,
  read, decoded or verified, no authorization flow is performed and no socket is
  opened. Proved by a module-resolution guard that refuses every network
  builtin while the binary completes a real run, by a live loopback listener
  whose address is planted in the input and never contacted, and by a scan of
  everything that ships.
- Read-only: the tool opens files for reading and writes nothing.
- Path confinement resolves the real path of both the root and each input, so a
  symlink planted inside the root is refused while a legitimate file under a
  symlinked root is not.
- Strict UTF-8 decoding on every input, the policy document included.
- Control (C0), DEL, C1, line/paragraph separator and bidi characters are
  stripped from every untrusted string that reaches output, identifiers and
  object keys included.
- A JSON parse failure is reported by position, line and column, never by
  quoting the document. V8 embeds the input in one of its two parse-error
  shapes (`Unexpected token 'A', "AKIA..." is not valid JSON`), and excerpting
  does not remove it: the quoted copy carries no control characters and sits at
  the front of the message. A client document short enough to be only a secret
  was therefore reproduced in full by `input-not-json`, in the report on stdout.
- No credential appears in any fixture. Example key sets carry public keys
  generated for this repository with their private halves discarded, and
  redaction is tested against published placeholders on both streams, for every
  prefix.

No release has been published.
