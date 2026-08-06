# v0.2 API Security Companion Pro — scope

Technical scope for the optional paid tier, gated behind
`LicensingFacade`:

- Kotlin support for Excessive Data Exposure / Mass Assignment (the two
  OWASP checks in the free tier are Java-only today).
- Shared team policy rules via a VCS-tracked file (today configuration
  is a local `PersistentStateComponent`, not shareable).
- Broken Object Level Authorization (OWASP API1) and Unrestricted
  Resource Consumption (OWASP API4) checks.

Only applied to Marketplace's Freemium pricing model once this code
exists, is tested, and passes `verifyPlugin` — never before the paid
feature is real and verifiable.
