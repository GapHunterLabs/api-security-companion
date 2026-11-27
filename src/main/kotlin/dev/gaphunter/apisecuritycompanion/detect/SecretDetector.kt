package dev.gaphunter.apisecuritycompanion.detect

data class SecretFinding(val kind: String, val description: String)

/**
 * Pure text-based secret detection — no PSI dependency, so the exact
 * matching rules can be unit tested in isolation from the platform.
 * Combines known credential-format signatures (AWS/GitHub/Slack/JWT/PEM
 * private keys, Stripe, and the AI-service and developer-platform tokens
 * listed in [SIGNATURES]) with a variable-name + Shannon-entropy
 * heuristic for the generic "some secret assigned to a suspiciously-named
 * field" case that no fixed format covers.
 *
 * The signatures are split from the heuristic on purpose: an exact format
 * (a fixed prefix plus a fixed-length body) is a near-certain finding and
 * stays Free everywhere it is scanned, while the entropy heuristic is the
 * one that guesses -- see [ConfigSecretScanner] for where that split
 * matters (it's a Pro check in configuration files).
 */
object SecretDetector {

    /**
     * The literals every match must contain ([LITERALS]) are checked with a plain `contains` before the regex runs: with 32 signatures, a line no longer pays 32 regex passes for the few that could
     * match. The check only skips a regex that could not match, so what is detected does not change.
     */
    private class Signature(val kind: String, val regex: Regex, val describe: (String) -> String) {
        val literals: List<String> = LITERALS[kind] ?: emptyList()
    }

    /** Text every match of a rule contains (one of them); rules not listed always run their regex. */
    private val LITERALS: Map<String, List<String>> = mapOf(
        "AWS_ACCESS_KEY" to listOf("AKIA", "ASIA"), "GITHUB_TOKEN" to listOf("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
        "SLACK_TOKEN" to listOf("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"), "JWT" to listOf("eyJ"), "PRIVATE_KEY" to listOf("-----BEGIN"),
        "STRIPE_KEY" to listOf("k_live_", "k_test_"), "OPENAI_API_KEY" to listOf("sk-"), "ANTHROPIC_API_KEY" to listOf("sk-ant-"),
        "HUGGINGFACE_TOKEN" to listOf("hf_", "api_org_"), "GROQ_API_KEY" to listOf("gsk_"), "PERPLEXITY_API_KEY" to listOf("pplx-"),
        "GOOGLE_API_KEY" to listOf("AIza"), "GITHUB_FINE_GRAINED_TOKEN" to listOf("github_pat_"), "GITLAB_TOKEN" to listOf("glpat-"),
        "NPM_TOKEN" to listOf("npm_"), "PYPI_TOKEN" to listOf("pypi-AgEIcHlwaS5vcmc"), "SENDGRID_API_KEY" to listOf("SG."),
        "SHOPIFY_TOKEN" to listOf("shpat_", "shpca_", "shppa_", "shpss_"), "DIGITALOCEAN_TOKEN" to listOf("dop_v1_"),
        "DATABRICKS_TOKEN" to listOf("dapi"), "VAULT_TOKEN" to listOf("hvs."), "SLACK_WEBHOOK" to listOf("hooks.slack.com/"),
        "ATLASSIAN_API_TOKEN" to listOf("ATATT3"), "DOPPLER_TOKEN" to listOf("dp.pt."), "AGE_SECRET_KEY" to listOf("AGE-SECRET-KEY-1"),
        "LINEAR_API_KEY" to listOf("lin_api_"), "POSTMAN_API_KEY" to listOf("PMAK-"), "GRAFANA_SERVICE_ACCOUNT_TOKEN" to listOf("glsa_"),
        "SQUARE_ACCESS_TOKEN" to listOf("sq0atp-"), "PUTTY_PRIVATE_KEY" to listOf("PuTTY-User-Key-File-"),
        "AZURE_STORAGE_KEY" to listOf("AccountKey="), "BCRYPT_HASH" to listOf("$2"),
    )

    /** Characters people use to redact a token by hand (`ghp_XXXX...`, `sk-proj-****...`). */
    private const val REDACTION = "Xx*#.-_0"

    /**
     * A redacted example, not a leak: at least 90 % of the body after the literal prefix is redaction characters
     * (a real token never comes close), or it is AWS's own documentation example key, which ends in `EXAMPLE`
     * (`AKIAIOSFODNN7EXAMPLE`). Headers (PEM, PuTTY) have no body to judge.
     */
    private fun isPlaceholder(signature: Signature, match: String): Boolean {
        if (signature.kind == "PRIVATE_KEY" || signature.kind == "PUTTY_PRIVATE_KEY") return false
        if (signature.kind == "AWS_ACCESS_KEY" && match.endsWith("EXAMPLE")) return true
        val lit = signature.literals.firstOrNull { match.contains(it) }
        val body = if (lit == null) match else match.substring(match.indexOf(lit) + lit.length)
        if (body.length < 8) return false
        return body.count { it in REDACTION } >= body.length * 0.9
    }

    /**
     * Formats with a distinctive prefix and a fixed-shape body, so a match is
     * a finding on its own. Order matters only for the first six, kept exactly
     * as they were before the list existed (the older detectors' messages are
     * part of the plugin's behavior); everything after them was added from the
     * default rule set of gitleaks (the widely used open-source scanner) and
     * from each vendor's own token documentation -- the same "fixed prefix,
     * fixed length" bar as the Stripe rule.
     *
     * Bodies are only ever shown as a short prefix in the warning text, never
     * in full.
     */
    private val SIGNATURES: List<Signature> = listOf(
        Signature("AWS_ACCESS_KEY", Regex("""\b(AKIA|ASIA)[0-9A-Z]{16}\b""")) {
            "Looks like an AWS access key ID (${it.take(8)}...)"
        },
        Signature("GITHUB_TOKEN", Regex("""\bgh[pousr]_[A-Za-z0-9]{36,}\b""")) {
            "Looks like a GitHub personal access token"
        },
        Signature("SLACK_TOKEN", Regex("""\bxox[baprs]-[0-9A-Za-z-]{10,}\b""")) {
            "Looks like a Slack API token"
        },
        // Starts only where the previous character is not a base64url character (was `\b`, which also allowed a start
        // right after `-`): a long `-eyJ-eyJ...` run with no `.` gave one start per `eyJ`, each scanning to the end of
        // the run, so the time grew with the square of the length. Only change in what matches: a JWT glued to a
        // preceding base64url character (`x-eyJ...`) is not reported.
        Signature("JWT", Regex("""(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b""")) {
            "Looks like a JWT (base64url header.payload.signature)"
        },
        // Any PEM or PGP private key header: RSA, EC, DSA, OPENSSH, ENCRYPTED, PKCS#8 and `PGP PRIVATE KEY BLOCK`
        // (the general header of gitleaks' private-key rule; the message stays the one users know).
        Signature("PRIVATE_KEY", Regex("""-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----""")) {
            "Contains a PEM private key block"
        },
        // Stripe secret/restricted API keys -- sk_live_.../rk_live_...
        // (sk_test_/rk_test_ too, since a hardcoded test key still leaks
        // real account structure and is a real finding worth flagging).
        Signature("STRIPE_KEY", Regex("""\b[sr]k_(live|test)_[A-Za-z0-9]{20,}\b""")) {
            "Looks like a Stripe secret/restricted API key (${it.take(11)}...)"
        },

        // --- AI services (the fastest-growing category of leaked secrets) ---
        // sk-proj-/sk-svcacct-/sk-admin- keys, plus the older sk-...T3BlbkFJ...
        // shape ("T3BlbkFJ" is base64 for "OpenAI").
        Signature(
            "OPENAI_API_KEY",
            Regex("""\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"""),
        ) { "Looks like an OpenAI API key (${it.take(8)}...)" },
        Signature("ANTHROPIC_API_KEY", Regex("""\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,}""")) {
            "Looks like an Anthropic API key (${it.take(10)}...)"
        },
        // hf_ user tokens and api_org_ organization tokens: 34 letters, no digits.
        Signature("HUGGINGFACE_TOKEN", Regex("""\b(?:hf|api_org)_[A-Za-z]{34}\b""")) {
            "Looks like a Hugging Face access token"
        },
        Signature("GROQ_API_KEY", Regex("""\bgsk_[A-Za-z0-9]{52}\b""")) { "Looks like a Groq API key" },
        Signature("PERPLEXITY_API_KEY", Regex("""\bpplx-[A-Za-z0-9]{48}\b""")) { "Looks like a Perplexity API key" },
        // A Google API key. Firebase web keys share this shape and are meant to
        // be public (restricted by referrer/app), so the message says to check.
        Signature("GOOGLE_API_KEY", Regex("""\bAIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])""")) {
            "Looks like a Google API key (${it.take(8)}...) -- fine if it's a restricted Firebase web key, a leak if not"
        },

        // --- developer platforms and cloud services ---
        Signature("GITHUB_FINE_GRAINED_TOKEN", Regex("""\bgithub_pat_\w{82}\b""")) {
            "Looks like a GitHub fine-grained personal access token"
        },
        Signature("GITLAB_TOKEN", Regex("""\bglpat-[\w-]{20}(?![\w-])""")) { "Looks like a GitLab personal access token" },
        Signature("NPM_TOKEN", Regex("""\bnpm_[A-Za-z0-9]{36}\b""")) { "Looks like an npm access token" },
        Signature("PYPI_TOKEN", Regex("""\bpypi-AgEIcHlwaS5vcmc[\w-]{50,}""")) { "Looks like a PyPI upload token" },
        Signature("SENDGRID_API_KEY", Regex("""\bSG\.[A-Za-z0-9=_.-]{66}(?![A-Za-z0-9=_.-])""")) { "Looks like a SendGrid API key" },
        Signature("SHOPIFY_TOKEN", Regex("""\bshp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32}\b""")) {
            "Looks like a Shopify access token"
        },
        Signature("DIGITALOCEAN_TOKEN", Regex("""\bdop_v1_[a-f0-9]{64}\b""")) {
            "Looks like a DigitalOcean personal access token"
        },
        Signature("DATABRICKS_TOKEN", Regex("""\bdapi[a-f0-9]{32}(?:-\d)?\b""")) { "Looks like a Databricks access token" },
        Signature("VAULT_TOKEN", Regex("""\bhvs\.[\w-]{90,120}""")) { "Looks like a HashiCorp Vault service token" },
        Signature(
            "SLACK_WEBHOOK",
            Regex("""hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}"""),
        ) { "Contains a Slack incoming-webhook URL (anyone with it can post to the channel)" },

        // --- same as secret-scanner-cli 0.3.0: shapes from gitleaks' rule set (read 2026-11-27) where they need no
        // nearby keyword, and three fixed formats from their own specification (PuTTY's key file header, Azure
        // Storage's 64-byte account key in a connection string, bcrypt's `$2a$NN$` + 53 characters) ---
        Signature("ATLASSIAN_API_TOKEN", Regex("""\bATATT3[A-Za-z0-9_\-=]{186}(?![A-Za-z0-9_\-=])""")) { "Looks like an Atlassian API token" },
        Signature("DOPPLER_TOKEN", Regex("""\bdp\.pt\.[A-Za-z0-9]{43}(?![A-Za-z0-9])""")) { "Looks like a Doppler personal token" },
        Signature("AGE_SECRET_KEY", Regex("""\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}(?![A-Z0-9])""")) {
            "Contains an age encryption secret key"
        },
        Signature("LINEAR_API_KEY", Regex("""\blin_api_[A-Za-z0-9]{40}(?![A-Za-z0-9])""")) { "Looks like a Linear API key" },
        Signature("POSTMAN_API_KEY", Regex("""\bPMAK-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{34}(?![A-Fa-f0-9])""")) { "Looks like a Postman API key" },
        Signature("GRAFANA_SERVICE_ACCOUNT_TOKEN", Regex("""\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}(?![A-Za-z0-9_])""")) {
            "Looks like a Grafana service account token"
        },
        Signature("SQUARE_ACCESS_TOKEN", Regex("""\bsq0atp-[\w-]{22,60}(?![\w-])""")) { "Looks like a Square access token" },
        Signature("PUTTY_PRIVATE_KEY", Regex("""PuTTY-User-Key-File-[23]:[ \t]*[A-Za-z0-9@.-]+""")) { "Contains a PuTTY private key file" },
        Signature("AZURE_STORAGE_KEY", Regex("""AccountKey=[A-Za-z0-9+/]{86}==""")) {
            "Contains an Azure Storage account key in a connection string"
        },
        Signature("BCRYPT_HASH", Regex("""\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}(?![./A-Za-z0-9])""")) {
            "Contains a bcrypt password hash (crackable offline if the password is weak)"
        },
    )

    /** Every rule id the signatures can report, in a fixed order. */
    val SIGNATURE_KINDS: List<String> get() = SIGNATURES.map { it.kind }

    private val SECRET_LIKE_NAME = Regex(
        """(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|private[_-]?key)""",
        RegexOption.IGNORE_CASE,
    )

    private val OBVIOUS_PLACEHOLDER = Regex(
        """^(|changeme|change[_-]?me|replace[_-]?me|todo|fixme|xxx+|your[_-].*|placeholder|example|test|dummy|<.*>|\$\{.*})$""",
        RegexOption.IGNORE_CASE,
    )

    private const val MIN_ENTROPY_LENGTH = 12
    private const val MIN_ENTROPY_BITS_PER_CHAR = 3.3

    /**
     * Only the exact-format signatures -- no name hint, no entropy guess. The first match that is not a
     * redacted placeholder wins, so `ghp_XXXX... and ghp_<real>` on one line still reports the real one.
     */
    fun scanSignatures(value: String): SecretFinding? {
        for (signature in SIGNATURES) {
            if (signature.literals.isNotEmpty() && signature.literals.none { value.contains(it) }) continue
            for (match in signature.regex.findAll(value)) {
                if (isPlaceholder(signature, match.value)) continue
                return SecretFinding(signature.kind, signature.describe(match.value))
            }
        }
        return null
    }

    fun scanLiteral(value: String, variableNameHint: String? = null): SecretFinding? {
        scanSignatures(value)?.let { return it }
        if (variableNameHint != null && isSecretLikeName(variableNameHint) && looksLikeARealSecret(value)) {
            return SecretFinding(
                "GENERIC_HIGH_ENTROPY",
                "Assigned to a variable named '$variableNameHint' and looks like a real credential, not a placeholder",
            )
        }
        return null
    }

    fun isSecretLikeName(name: String): Boolean = SECRET_LIKE_NAME.containsMatchIn(name)

    fun looksLikeARealSecret(value: String): Boolean {
        if (value.length < MIN_ENTROPY_LENGTH) return false
        if (OBVIOUS_PLACEHOLDER.matches(value.trim())) return false
        if (value.toSet().size <= 2) return false
        return shannonEntropyBitsPerChar(value) >= MIN_ENTROPY_BITS_PER_CHAR
    }

    fun shannonEntropyBitsPerChar(value: String): Double {
        if (value.isEmpty()) return 0.0
        val counts = value.groupingBy { it }.eachCount()
        val length = value.length.toDouble()
        return -counts.values.sumOf { count ->
            val p = count / length
            p * (Math.log(p) / Math.log(2.0))
        }
    }
}
