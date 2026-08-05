<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# API Security Companion Changelog

## [Unreleased]

## [2026.1.0]

### Changed

- **Version scheme**: this plugin now versions as `YYYY.MINOR.PATCH`
  (JetBrains's own convention for Paid/Freemium plugins) instead of
  semver (`0.2.x`) -- required by the same hard Marketplace validation
  rule already hit with `ansible-companion` and `openapi-companion`:
  `<product-descriptor>`'s `release-version` must share its leading
  digits with the plugin's own version.

### Added

- `<product-descriptor>` in `plugin.xml`, with the real product code
  JetBrains Marketplace assigned on applying for the Freemium pricing
  model: `code="[REDACTED-PRODUCT-CODE]"`, `optional="true"` -- the free tier
  stays fully functional with no license, only Pro features gate.

## [0.2.0]

### Added

- **API Security Companion Pro** (optional paid tier, gated behind
  `LicensingFacade`):
  - Kotlin support for Excessive Data Exposure / Mass Assignment — the
    two OWASP checks from 0.1.0 were Java-only; type-annotation
    resolution now works for Kotlin functions/parameters too, including
    a Kotlin function referencing a Java-declared entity class.
  - Broken Object Level Authorization (OWASP API1): flags a REST
    endpoint with an object-ID-shaped parameter and no visible
    authorization/ownership check in its body. A heuristic, always
    framed as "potential" — not a data-flow analysis.
  - Unrestricted Resource Consumption (OWASP API4): flags a page-size/
    limit-shaped parameter with no upper-bound validation annotation.
  - Team rules shared via VCS: a `.gaphunter-security-rules` file
    (one rule ID per line) committed to the project root forces those
    rules on for every team member who opens the project, regardless of
    their own local Settings — a rule the team agreed on can't be
    silently disabled by one person.
- All Pro checks are registered unconditionally (the plugin loads
  identically for everyone); only the paid feature itself gates on
  license or the team policy file, per this workspace's own established
  Freemium pattern.

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

### Known gaps (resolved in 0.2.0)

- Excessive Data Exposure / Mass Assignment checks are Java-only; Kotlin
  support needs its own annotation-resolution path.

[Unreleased]: https://github.com/GapHunterLabs/api-security-companion/compare/2026.1.0...HEAD
[2026.1.0]: https://github.com/GapHunterLabs/api-security-companion/compare/0.2.0...2026.1.0
[0.2.0]: https://github.com/GapHunterLabs/api-security-companion/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/GapHunterLabs/api-security-companion/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/GapHunterLabs/api-security-companion/commits/0.1.0
