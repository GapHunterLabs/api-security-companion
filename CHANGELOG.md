<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# API Security Companion Changelog

## [Unreleased]

## [2026.4.2]

### Fixed

- The plugin now includes `META-INF/THIRD-PARTY-NOTICES.txt` with the license notices of the
  open-source libraries it bundles (KInference, fastutil, Okio, Wire, atomicfu, Apache Commons Math and Numbers, and SLF4J),
  including the full text of the Apache License 2.0, as that license requires.

## [2026.4.1]

### Fixed

- The plugin no longer ships its own copy of the Kotlin standard library
  (2.0.0 and 1.9.10), `kotlin-test` or `kotlinx-coroutines-test`, which the
  inference library pulled in. It now uses the IDE's own Kotlin runtime, as
  JetBrains recommends, and the download is smaller.

### Changed

- The rating prompt's local counter keeps one-way fingerprints of findings
  instead of their file paths, and deletes the list that earlier versions
  kept.
- `PRIVACY.md` describes the values the plugin keeps in the IDE's local
  settings.

## [2026.4.0]

### Added

- **Secrets in configuration files, not only Java/Kotlin literals.** Known-format
  tokens are now found in JSON, YAML, `.properties` and `.env` files
  (`.env.local`, `.env.production`, ...), including the MCP server configs that
  AI tools read (`mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`,
  `claude_desktop_config.json`), where API keys are routinely pasted into `env`
  and `headers`. Free. Skipped on purpose: `.env.example`/`*.sample`/`*.template`
  files, lock files, `google-services.json`, build and dependency directories, and
  anything under a key called `example` or `description` (OpenAPI specs are full of
  sample tokens). References such as `${OPENAI_API_KEY}` are never reported. New
  rule "Known-format secrets ... in JSON, YAML, .properties and .env files" in
  Settings -> Tools -> API Security Companion.
- **AI-service and developer-platform token formats**, in code and in config
  files: OpenAI, Anthropic, Hugging Face, Groq, Perplexity, Google API keys,
  GitHub fine-grained tokens, GitLab, npm, PyPI, SendGrid, Shopify, DigitalOcean,
  Databricks, HashiCorp Vault, and Slack incoming-webhook URLs. Each is a fixed
  prefix plus a fixed-length body (the same bar as the Stripe rule), taken from the
  default rule set of the open-source scanner gitleaks and each vendor's own token
  documentation. The warning shows only a short prefix, never the whole token.
- **Pro:** credential-named keys with a high-entropy value in configuration files
  (`client_secret`, `DB_PASSWORD`, `Authorization: Bearer ...`, `--api-key=...`),
  stricter than the Java-literal heuristic: the credential word has to be the
  key's last word (`token_url` and `secretName` are settings about a secret, not
  secrets), and URLs, paths, sentences, slugs and references are never values.

### Fixed

- Review/star CTA now links to this plugin's own Marketplace
  reviews page instead of the vendor's generic plugin list.

## [2026.3.0]

### Added

- **ML false-positive reduction** on the generic, entropy-based secret
  match (Pro, off by default even with a license — enable it from
  Settings): a small model (under 20KB) re-checks that specific case
  before showing a warning, to cut down on false alarms for UUIDs,
  hashes, and similar high-entropy-but-not-secret values. Runs 100%
  on-device, no network calls. Never applies to a recognized format
  (AWS key, GitHub/Slack token, JWT, PEM block, Stripe key) — those
  stay exact matches, unaffected. Tuned deliberately conservative: it
  only suppresses a warning when confident, since missing a real
  secret is a far worse outcome than one extra warning shown — that's
  also why it ships off by default instead of following every other
  rule's "on unless you turn it off" pattern.

## [2026.2.0]

### Added

- Detects hardcoded Stripe secret/restricted API keys
  (`sk_live_`/`sk_test_`/`rk_live_`/`rk_test_`) alongside the existing
  AWS/GitHub/Slack/JWT/PEM detection -- one of the most standard
  secret-scanning rules that exists (GitHub Secret Scanning,
  TruffleHog, and gitleaks all treat this as a top-priority pattern),
  a real gap for a plugin whose own detectors already cover
  payment/API-adjacent risk.

## [2026.1.2]

### Added

- Review/star CTA: after 10 distinct real findings across any of the
  6 detectors (excessive data exposure, mass assignment, hardcoded
  secrets, insecure transport, trust-all TLS, OpenAPI spec issues, and
  the Pro-tier BOLA/resource-consumption/Kotlin checks), a one-time
  notification asks whether to rate the plugin on Marketplace, with a
  permanent "Don't ask again" option. Standard mechanism used
  catalog-wide since 2026-08-24, rolled out
  to this plugin now.

## [2026.1.1]

### Fixed

- Removed internal Marketplace/monetization-planning details that had
  been mistakenly documented in public files -- no user-facing change.

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
  model -- `optional="true"` is what keeps the free tier fully
  functional with no license, only Pro features gate.

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

[Unreleased]: https://github.com/GapHunterLabs/api-security-companion/compare/2026.4.2...HEAD
[2026.4.2]: https://github.com/GapHunterLabs/api-security-companion/compare/2026.4.1...2026.4.2
[2026.4.1]: https://github.com/GapHunterLabs/api-security-companion/compare/2026.4.0...2026.4.1
[2026.4.0]: https://github.com/GapHunterLabs/api-security-companion/compare/2026.3.0...2026.4.0
[2026.3.0]: https://github.com/GapHunterLabs/api-security-companion/compare/2026.2.0...2026.3.0
[2026.2.0]: https://github.com/GapHunterLabs/api-security-companion/compare/2026.1.2...2026.2.0
[2026.1.2]: https://github.com/GapHunterLabs/api-security-companion/compare/2026.1.1...2026.1.2
[2026.1.1]: https://github.com/GapHunterLabs/api-security-companion/compare/2026.1.0...2026.1.1
[2026.1.0]: https://github.com/GapHunterLabs/api-security-companion/compare/0.2.0...2026.1.0
[0.2.0]: https://github.com/GapHunterLabs/api-security-companion/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/GapHunterLabs/api-security-companion/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/GapHunterLabs/api-security-companion/commits/0.1.0
