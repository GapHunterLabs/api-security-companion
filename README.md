# API Security Companion

IntelliJ/Android Studio plugin. Lightweight, 100% local API-security
checks for Java and Kotlin — hardcoded secrets, plaintext HTTP, TLS
misconfiguration, and OWASP API Security Top 10 patterns.

## Why it exists

Built after reviewing real, recent reviews of the market-leading security
scanners, not assumptions:

- **Snyk Security** (759K downloads, 85% ≤3★): recurring 2024-2026 reports
  of IDE freezes and crashes during scans ("Freezes Rider on scans. Have
  to kill process in TaskManager"), broken suppression/ignore logic, and
  background processes flagged by antivirus software.
- **Qodana Security Analysis** (JetBrains' own, 88% ≤3★): the "Taint
  Analysis" button is disabled out of the box with no clear way to enable
  it, and using it at all turns out to require a $180/year "Ultimate
  Plus" subscription that isn't disclosed until checkout.
- **OpenAPI Specifications** (JetBrains' own, 8M downloads, 70% ≤3★):
  "catastrophically slow... turned into torture" editing/rendering
  OpenAPI documents, IDE hangs even on small 10-15-endpoint files.

None of these are financially beatable — they're free or backed by
well-funded vendors. The gap isn't "cheaper than Snyk," it's "actually
works, never freezes the IDE, and never phones home."

## What it checks

- **Hardcoded secrets**: AWS access keys, GitHub/Slack tokens, JWTs, PEM
  private key blocks, plus a variable-name + Shannon-entropy heuristic
  for the generic case (`val apiSecret = "..."` with a high-entropy
  value that isn't an obvious placeholder).
- **Plaintext HTTP** to non-local hosts.
- **TLS trust managers that accept every certificate** (CWE-295) —
  the classic empty `checkServerTrusted`/`checkClientTrusted`.
- **Excessive Data Exposure / Mass Assignment** (OWASP API Security Top
  10, Java only in this release): REST endpoints that return a
  persistence entity directly, or bind a request body straight onto one.
- **OpenAPI spec checks**: an empty top-level `security:` scheme, and
  wildcard CORS (`Access-Control-Allow-Origin: *`) combined with
  `Access-Control-Allow-Credentials: true`.

## Why built this way

- **No network calls, no cloud dashboard.** Every check runs in-process
  against the code already open in the editor. This is the direct fix
  for Snyk's auth failures, mystery background processes, and the
  general enterprise concern about sending source code to a third-party
  cloud for scanning.
- **Every rule is a normal `Annotator`**, which the platform's own
  highlighting daemon already schedules during its background pass —
  not on the UI thread. This is the direct fix for the "freezes the IDE
  during scans" complaint common to Snyk and to JetBrains' own OpenAPI
  Specifications plugin.
- **Every rule can be disabled individually**, with no exceptions — the
  direct fix for Qodana's Taint Analysis being un-disableable and
  undisclosed-paywalled at the same time.
- **Pure-Kotlin detection logic, separated from PSI walking** (see
  `detect/`), so every rule's exact matching behavior is unit-tested
  without needing to spin up the platform.
- **No YAML/JSON parser dependency** for the OpenAPI checks — targeted
  line-based regexes are enough for "does this key exist with this
  value," and a full spec parser is exactly the kind of heavyweight
  approach that made the OpenAPI Specifications plugin slow in the first
  place.

## Development

```
./gradlew test           # unit tests
./gradlew buildPlugin     # generates build/distributions/*.zip
./gradlew verifyPlugin    # checks compatibility against real IDEs
```

## License

Apache-2.0. See `LICENSE`.
