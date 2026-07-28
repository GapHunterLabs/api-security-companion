package dev.gaphunter.apisecuritycompanion.settings

enum class SecurityRule(val id: String, val displayName: String) {
    SECRET_DETECTION("secretDetection", "Hardcoded secrets and API keys"),
    INSECURE_HTTP("insecureHttp", "Plaintext HTTP URLs to remote hosts"),
    TRUST_ALL_CERTIFICATES("trustAllCertificates", "TLS trust managers that accept every certificate"),
    EXCESSIVE_DATA_EXPOSURE("excessiveDataExposure", "REST endpoints returning a persistence entity directly"),
    MASS_ASSIGNMENT("massAssignment", "REST write endpoints binding a request body onto a persistence entity"),
    OPENAPI_MISSING_SECURITY("openApiMissingSecurity", "OpenAPI specs with an empty top-level security scheme"),
    OPENAPI_PERMISSIVE_CORS("openApiPermissiveCors", "OpenAPI specs with wildcard CORS + credentials"),
}
