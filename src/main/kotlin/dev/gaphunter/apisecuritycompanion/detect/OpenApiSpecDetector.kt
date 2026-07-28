package dev.gaphunter.apisecuritycompanion.detect

data class SpecFinding(val kind: String, val line: Int, val description: String)

/**
 * Line-based checks over raw OpenAPI/Swagger YAML or JSON text. No YAML/
 * JSON parser dependency — the two checks here only need to notice
 * whether certain keys/values appear at all, which a handful of regexes
 * over the raw lines does correctly for the well-formed specs these
 * checks are meant to catch problems in. A full spec parser is exactly
 * the kind of heavyweight, slow-to-render approach that made JetBrains'
 * own OpenAPI Specifications plugin infamous for freezing the IDE —
 * deliberately not repeating that mistake here.
 */
object OpenApiSpecDetector {

    private val TOP_LEVEL_SECURITY_KEY = Regex("""^security\s*:\s*(\[\s*])?\s*$""")
    private val EMPTY_LIST_MARKER = Regex("""^\s*\[\s*]\s*$""")
    private val WILDCARD_ORIGIN = Regex("""Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]?\*""", RegexOption.IGNORE_CASE)
    private val ALLOW_CREDENTIALS_TRUE = Regex("""Access-Control-Allow-Credentials['"]?\s*[:=]\s*['"]?true""", RegexOption.IGNORE_CASE)

    fun hasEmptyTopLevelSecurity(specText: String): SpecFinding? {
        val lines = specText.lines()
        for ((index, line) in lines.withIndex()) {
            val match = TOP_LEVEL_SECURITY_KEY.matchEntire(line) ?: continue
            val hasInlineEmptyList = match.groupValues[1].isNotEmpty()
            val next = lines.getOrNull(index + 1)?.trim()
            val isEmpty = hasInlineEmptyList ||
                next == null || EMPTY_LIST_MARKER.matches(next) || !next.startsWith("-")
            if (isEmpty) {
                return SpecFinding(
                    "EMPTY_SECURITY_SCHEME",
                    index + 1,
                    "Top-level 'security:' has no scheme listed — every endpoint that doesn't override it is unauthenticated",
                )
            }
        }
        return null
    }

    fun findWildcardCorsWithCredentials(specText: String): SpecFinding? {
        val hasWildcard = WILDCARD_ORIGIN.containsMatchIn(specText)
        val hasCredentials = ALLOW_CREDENTIALS_TRUE.containsMatchIn(specText)
        if (!hasWildcard || !hasCredentials) return null

        val lines = specText.lines()
        val lineIndex = lines.indexOfFirst { WILDCARD_ORIGIN.containsMatchIn(it) }
        return SpecFinding(
            "PERMISSIVE_CORS_WITH_CREDENTIALS",
            (if (lineIndex >= 0) lineIndex else 0) + 1,
            "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true — browsers reject this combination, and proxies that allow it expose credentialed requests to any origin",
        )
    }
}
