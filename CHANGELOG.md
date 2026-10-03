# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-10-03

### Changed

- `Altcha.V2.verify_solution/1` and `Altcha.V2.verify_server_signature/2` raise
  `ArgumentError` when the HMAC secret is `nil` or `""`, like the JS reference (Web Crypto
  rejects zero-length HMAC keys). Previously `""` returned `invalid_signature: true` and
  `nil` raised an unclear `:crypto` error.
- `Altcha.Plug.Challenge` raises `ArgumentError` for a `nil` or empty
  `:hmac_signature_secret`: in `init/1` for a string, and per request for a function or
  MFA tuple (e.g. an empty environment variable). Previously it served unsigned
  challenges that could never verify.
- `Altcha.V2.create_challenge/1` raises `ArgumentError` for a non-hex `key_prefix`, which
  previously produced a challenge no solver could match.

### Fixed

- `Altcha.V2.verify_solution/1` returns `invalid_solution: true` instead of raising when
  the client-submitted `derivedKey` is not valid hex (non-hex characters, odd length) or
  is missing / not a string, on both the key-signature and re-derivation paths.
- `key_prefix` is always lowercase: `Altcha.V2.create_challenge/1` lowercases the
  `key_prefix` option, and `solve_challenge/1` / `verify_solution/1` match a signed
  prefix case-insensitively, for even and odd lengths alike. Previously verify compared
  even-length prefixes case-sensitively, so an uppercase prefix such as `"0A"` rejected
  the solver's own solution.
- `Altcha.V2.verify_solution/1` expiry matches the JS reference: the challenge expires
  once `expiresAt` is earlier than the current time with fractional seconds (previously
  floored, granting up to 1 s of grace), and `expiresAt: 0` means no expiry (previously
  treated as expired).
- `Altcha.V2.verify_server_signature/2` expiry matches the JS reference: `expire=0`
  means no expiry (previously treated as expired), and a decimal `expire` is checked
  (previously ignored).
- The canonical JSON signed by `Altcha.V2` is byte-identical to the JS reference
  (`JSON.stringify(sortKeys(parameters))`): JS number formatting (`1.0` → `1`,
  `1e21` → `1e+21`, integers beyond 2^53 rounded to the nearest double), array-index keys
  (`"9"`, `"10"`) first in numeric order followed by UTF-16 key order, and lowercase
  `\u00xx` control-character escapes. Previously a challenge whose `data` held a float
  such as `1.0` failed `invalid_signature` after the widget re-serialized it, and
  JS-signed challenges with such data did not verify.
- `Altcha.V2` treats an empty-string secret or `keySignature` as unset, like the JS
  reference: `create_challenge/1` with `hmac_signature_secret: ""` returns an unsigned
  challenge, `hmac_key_signature_secret: ""` adds no `keySignature`, and
  `verify_solution/1` re-derives the key when either is `""`. Previously `""` was used
  as an empty HMAC key.
- `Altcha.V2.verify_solution/1` and `verify_server_signature/2` no longer raise on
  malformed client input. A numeric `counter` follows JS number semantics (a JSON `7.0`
  verifies like `7`; uint32 mode truncates and wraps modulo 2^32, like `setUint32`), a
  non-numeric `counter` is `invalid_solution: true`, and a non-string signature is
  `invalid_signature: true`.
- `Altcha.V2.create_challenge/1` caps `key_prefix_length` at half the key length
  (`key_length / 2`, also the default), so the deterministic prefix never reveals more
  than half the key. Previously a larger value raised `ArgumentError`.
- `Altcha.V2.solve_challenge/1` returns `nil` for a challenge whose `key_prefix` is not
  hex, instead of raising (even length) or running until the timeout (odd length).
- `Altcha.V2.solve_challenge/1` treats `timeout: 0` as no timeout, like the JS reference,
  and also accepts `timeout: :infinity`. Previously `0` returned `nil` at once.
- `Altcha.V2.verify_server_signature/2` returns a failed result with `nil` verification
  data instead of raising when the client payload is missing, not JSON, not a JSON
  object, or has a missing / non-string `verificationData`. `Altcha.V2.decode_payload/1`
  returns `nil` for a missing (`nil`) or non-string payload.
- `Altcha.V2.verify_server_signature/2` keeps a `verificationData` value with a trailing
  newline (e.g. `"5\n"`) as a string, like the JS reference. Previously it was mistaken
  for a number, and the failed conversion discarded all verification data, so a valid
  payload did not verify.

## [2.1.0] - 2026-08-26

### Added

- `Altcha.Plug.Challenge` — a `Plug` that serves a freshly signed ALTCHA v2
  proof-of-work challenge as JSON, so the widget's `challenge` attribute can point straight
  at your app. Requires the new optional `:plug` dependency; nothing changes for
  non-Plug users.
- A [Phoenix integration guide](guides/phoenix.md) covering widget loading, the
  challenge endpoint, the LiveView `statechange` hook, and solution verification.

## [2.0.1] — 2026-07-30

### Fixed

- Enforce `key_prefix` in the proof-of-work fallback verification path.

## [2.0.0] — 2026-04-07

### Added

- `Altcha.V2` — key-derivation-based challenges (`PBKDF2`, iterative `SHA`) with
  tunable cost, for the ALTCHA widget v3.

### Changed

- The top-level `Altcha` module now delegates to `Altcha.V1` for backward
  compatibility. New code should call `Altcha.V1` / `Altcha.V2` directly.
