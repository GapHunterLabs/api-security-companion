package dev.gaphunter.apisecuritycompanion.settings

enum class SecurityRule(val id: String, val displayName: String, val defaultEnabled: Boolean = true) {
    SECRET_DETECTION("secretDetection", "Hardcoded secrets and API keys"),
    CONFIG_FILE_SECRETS(
        "configFileSecrets",
        "Known-format secrets (AI-service, cloud and developer tokens) in JSON, YAML, .properties and .env files, including MCP server configs",
    ),
    CONFIG_SECRET_HEURISTIC(
        "configSecretHeuristic",
        "Credential-named keys with a high-entropy value in configuration files (Pro)",
    ),
    INSECURE_HTTP("insecureHttp", "Plaintext HTTP URLs to remote hosts"),
    TRUST_ALL_CERTIFICATES("trustAllCertificates", "TLS trust managers that accept every certificate"),
    EXCESSIVE_DATA_EXPOSURE("excessiveDataExposure", "REST endpoints returning a persistence entity directly"),
    MASS_ASSIGNMENT("massAssignment", "REST write endpoints binding a request body onto a persistence entity"),
    OPENAPI_MISSING_SECURITY("openApiMissingSecurity", "OpenAPI specs with an empty top-level security scheme"),
    OPENAPI_PERMISSIVE_CORS("openApiPermissiveCors", "OpenAPI specs with wildcard CORS + credentials"),
    BROKEN_OBJECT_LEVEL_AUTH(
        "brokenObjectLevelAuth",
        "REST endpoints with an ID-shaped parameter and no visible authorization check (Pro)",
    ),
    UNRESTRICTED_RESOURCE_CONSUMPTION(
        "unrestrictedResourceConsumption",
        "Unbounded limit/page-size parameters with no upper-bound validation (Pro)",
    ),

    // Deliberately the only rule in this enum with defaultEnabled = false.
    // Every other rule only ADDS a warning -- a false positive there is a
    // minor annoyance. This one SUPPRESSES a warning the entropy
    // heuristic already decided to show; its failure mode is hiding a
    // real leaked secret, which is categorically worse. The user has to
    // opt in on purpose after reading what it does, even with a valid
    // Pro license -- see MlClassifierService for the conservative
    // suppression threshold this is paired with.
    ML_FALSE_POSITIVE_REDUCTION(
        "mlFalsePositiveReduction",
        "Reduce false positives on generic high-entropy secret matches using a local ML model (Pro, off by default)",
        defaultEnabled = false,
    ),
}
