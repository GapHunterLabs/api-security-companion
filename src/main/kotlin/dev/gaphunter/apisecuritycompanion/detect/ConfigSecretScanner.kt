package dev.gaphunter.apisecuritycompanion.detect

/** Where a scalar sits in a configuration document: the key it's assigned to and the keys that enclose it. */
data class ConfigContext(val key: String?, val ancestors: List<String> = emptyList())

/** A secret found in a line-based file (`.env`), with the value's offsets in the whole text. */
data class LineFinding(val finding: SecretFinding, val start: Int, val end: Int)

/**
 * Secret detection for configuration files -- JSON, YAML, `.properties` and
 * `.env`, including the MCP (Model Context Protocol) server configs that
 * AI tools read from `mcp.json`, `claude_desktop_config.json` and friends.
 * Pure text logic, no PSI, so every rule is unit-tested without the platform.
 *
 * Two tiers, on purpose:
 *  - **Exact formats** ([SecretDetector.scanSignatures]) are Free everywhere:
 *    a fixed prefix plus a fixed-length body is a near-certain finding.
 *  - The **name + entropy heuristic** is the part that guesses, so it is the
 *    Pro check here (`heuristicEnabled`), tuned stricter than the Java-literal
 *    version because configuration files are full of keys like `token_url`
 *    or `secretName` whose values are not secrets.
 */
object ConfigSecretScanner {

    /** Keys whose subtree holds sample data, not real credentials (OpenAPI `example`, etc.). */
    private val SAMPLE_KEYS = setOf("example", "examples", "sample", "samples", "description", "summary")

    /** A whole-value reference to something defined elsewhere: `${VAR}`, `$VAR`, `%VAR%`, `{{ var }}`, `<placeholder>`. */
    private val REFERENCE = Regex("""^\s*(\$\{[^}]*}|\$[A-Za-z_][A-Za-z0-9_]*|%[^%]+%|\{\{.*}}|<[^>]*>|env:[A-Za-z_]\w*)\s*$""")

    /**
     * Keys that name a credential. The LAST word has to be the credential noun --
     * `api_token`, `client_secret`, `DB_PASSWORD` yes; `token_url`, `secretName`,
     * `passwordPolicy` no -- because those are settings ABOUT a secret, not one.
     */
    private val CREDENTIAL_KEY = Regex(
        """(^|[_.\-\s])(api[_-]?key|access[_-]?key|private[_-]?key|secret[_-]?key|signing[_-]?key|encryption[_-]?key|""" +
            """secret|token|password|passwd|pwd|passphrase|credentials?|authorization|auth)$|[a-z0-9](ApiKey|AccessKey|""" +
            """PrivateKey|SecretKey|Secret|Token|Password|Passphrase|Credentials?|Authorization)$""",
        RegexOption.IGNORE_CASE,
    )

    private val AUTH_SCHEME_PREFIX = Regex("""^(Bearer|Basic|Token)\s+""", RegexOption.IGNORE_CASE)

    /** `--api-key=VALUE` / `-p=VALUE` command-line arguments, as MCP configs pass them in `args`. */
    private val FLAG_ASSIGNMENT = Regex("""^--?([A-Za-z][A-Za-z0-9_.-]*)=(.+)$""", RegexOption.DOT_MATCHES_ALL)

    private val USERINFO_IN_URL = Regex("""://[^/@\s]+:[^/@\s]+@""")
    // Letters only: `authorization-code-grant` is a slug, `acme_deploy_9f8e7d6c5b4a3210` is not (a digit run is what a
    // generated key looks like, and the corpus run showed a slug guard that allowed digits hid exactly that key).
    private val LOWER_SLUG = Regex("""[a-z]+([_.-][a-z]+)+""")
    private val UPPER_SLUG = Regex("""[A-Z]+([_.-][A-Z]+)+""")

    private val ENV_LINE = Regex("""^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(.*)$""")

    private val SKIPPED_DIRECTORIES = listOf(
        "/node_modules/", "/build/", "/target/", "/dist/", "/out/", "/.gradle/", "/.git/", "/vendor/",
    )

    private val MCP_FILE_NAMES = setOf(
        "mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_settings.json", "cline_mcp_settings.json", "mcp_config.json",
    )

    private val GENERATED_FILE_NAMES = setOf(
        "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "composer.lock", "pubspec.lock",
        "google-services.json",
    )

    private val TEMPLATE_MARKERS = listOf(".example", ".sample", ".template", ".dist", ".tpl", ".tmpl")

    /** Sample/template files and lock files are placeholders or hashes by design. */
    fun isTemplateOrGeneratedFile(fileName: String): Boolean {
        val name = fileName.lowercase()
        if (name in GENERATED_FILE_NAMES) return true
        return TEMPLATE_MARKERS.any { name.endsWith(it) || name.contains("$it.") }
    }

    fun isInSkippedDirectory(path: String): Boolean {
        val normalized = "/" + path.replace('\\', '/').trimStart('/')
        return SKIPPED_DIRECTORIES.any { normalized.contains(it) }
    }

    fun isMcpConfig(path: String): Boolean {
        val name = path.replace('\\', '/').substringAfterLast('/').lowercase()
        return name in MCP_FILE_NAMES
    }

    fun isReference(value: String): Boolean = REFERENCE.matches(value)

    /** True for a key that names a credential (last word is the credential noun). */
    fun isCredentialKey(key: String): Boolean = CREDENTIAL_KEY.containsMatchIn(key.trim())

    /**
     * Scans one scalar. [heuristicEnabled] is the Pro switch: without it only an
     * exact format is reported, regardless of how suspicious the key looks.
     */
    fun scanValue(value: String, context: ConfigContext, heuristicEnabled: Boolean): SecretFinding? {
        if (value.isBlank()) return null
        if ((context.ancestors + listOfNotNull(context.key)).any { it.lowercase() in SAMPLE_KEYS }) return null
        if (isReference(value)) return null

        SecretDetector.scanSignatures(value)?.let { return it }
        if (!heuristicEnabled) return null

        var key = context.key
        var core = value.trim()
        FLAG_ASSIGNMENT.matchEntire(core)?.let { match ->
            key = match.groupValues[1]
            core = match.groupValues[2]
        }
        core = core.replace(AUTH_SCHEME_PREFIX, "")
        val name = key ?: return null
        if (!isCredentialKey(name)) return null
        if (isReference(core) || !looksLikeACredentialValue(core)) return null
        if (!SecretDetector.looksLikeARealSecret(core)) return null
        return SecretFinding(
            "GENERIC_HIGH_ENTROPY",
            "Assigned to '$name' and looks like a real credential, not a placeholder or a reference",
        )
    }

    /**
     * Stricter than the Java-literal check: a credential value is one token, not a
     * sentence, path or URL, and mixes character classes.
     */
    private fun looksLikeACredentialValue(value: String): Boolean {
        if (value.any { it.isWhitespace() }) return false
        if (value.startsWith("/") || value.startsWith("./") || value.startsWith("~") || value.contains('\\')) return false
        if (value.contains("://") && !USERINFO_IN_URL.containsMatchIn(value)) return false
        // `authorization-code-grant`, `GITHUB_TOKEN_NAME`: identifiers and slugs, not credentials.
        if (LOWER_SLUG.matches(value) || UPPER_SLUG.matches(value)) return false
        val classes = listOf(
            value.any { it.isLowerCase() }, value.any { it.isUpperCase() },
            value.any { it.isDigit() }, value.any { !it.isLetterOrDigit() },
        ).count { it }
        return classes >= 2
    }

    /** `.env` files: `KEY=VALUE` and `export KEY=VALUE` lines, `#` comments, single/double quotes. */
    fun scanDotEnv(text: String, heuristicEnabled: Boolean): List<LineFinding> {
        val findings = mutableListOf<LineFinding>()
        var offset = 0
        for (rawLine in text.split("\n")) {
            val lineStart = offset
            offset += rawLine.length + 1
            val line = rawLine.trimEnd('\r')
            if (line.isBlank() || line.trimStart().startsWith("#")) continue
            val match = ENV_LINE.matchEntire(line) ?: continue
            val (prefix, key, equals, rest) = match.destructured
            val (value, valueOffset) = unquote(rest)
            val finding = scanValue(value, ConfigContext(key), heuristicEnabled) ?: continue
            val start = lineStart + prefix.length + key.length + equals.length + valueOffset
            findings += LineFinding(finding, start, start + value.length)
        }
        return findings
    }

    /** Strips one pair of quotes, or a trailing ` # comment` from an unquoted value; returns the value and its offset in [rest]. */
    private fun unquote(rest: String): Pair<String, Int> {
        val trimmed = rest.trimStart()
        val lead = rest.length - trimmed.length
        if (trimmed.length >= 2 && (trimmed[0] == '"' || trimmed[0] == '\'')) {
            val close = trimmed.indexOf(trimmed[0], 1)
            if (close > 0) return trimmed.substring(1, close) to (lead + 1)
        }
        val commentAt = Regex("""\s#""").find(trimmed)?.range?.first ?: trimmed.length
        return trimmed.substring(0, commentAt).trimEnd() to lead
    }
}
