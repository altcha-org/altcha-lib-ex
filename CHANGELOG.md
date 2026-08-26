# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-08-26

### Added

- `Altcha.Plug.Challenge` — a `Plug` that serves a freshly signed ALTCHA v2
  proof-of-work challenge as JSON, so the widget's `challengeurl` can point straight
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
  tunable cost, for the ALTCHA widget v2.

### Changed

- The top-level `Altcha` module now delegates to `Altcha.V1` for backward
  compatibility. New code should call `Altcha.V1` / `Altcha.V2` directly.
