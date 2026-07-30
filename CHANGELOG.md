<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# API Security Companion Changelog

## [Unreleased]

## [0.1.1]

### Fixed

- `AnnotationBuilder.range(element.textRange)` resolved against an
  `@ApiStatus.Experimental`-marked `PsiElement` subtype via Kotlin
  overload resolution, without the code ever referencing that type
  directly. Fixed by typing the range explicitly as `TextRange` before
  the `.range()` call, forcing the stable overload — `verifyPlugin` now
  reports zero experimental-API warnings across all 6 target IDEs.

## [0.1.0]

### Added

- Hardcoded secret detection (AWS access keys, GitHub/Slack tokens, JWTs,
  PEM private key blocks, plus a variable-name + Shannon-entropy
  heuristic for the generic case) in Java and Kotlin string literals.
- Plaintext HTTP URL detection, scoped to non-local hosts only.
- Detection of `X509TrustManager` implementations that accept every
  certificate (CWE-295).
- OWASP API Security Top 10 checks for Java: Excessive Data Exposure
  (REST endpoints returning a persistence entity directly) and Mass
  Assignment (REST write endpoints binding a request body onto a
  persistence entity).
- OpenAPI/Swagger spec checks: empty top-level `security` scheme, and
  wildcard CORS combined with `Access-Control-Allow-Credentials: true`.
- Every rule can be disabled individually in Settings — none of them are
  held back behind a paid tier.

### Known gaps (tracked for a future release)

- Excessive Data Exposure / Mass Assignment checks are Java-only; Kotlin
  support needs its own annotation-resolution path.

[Unreleased]: https://github.com/GapHunterLabs/api-security-companion/compare/0.1.1...HEAD
[0.1.1]: https://github.com/GapHunterLabs/api-security-companion/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/GapHunterLabs/api-security-companion/commits/0.1.0
