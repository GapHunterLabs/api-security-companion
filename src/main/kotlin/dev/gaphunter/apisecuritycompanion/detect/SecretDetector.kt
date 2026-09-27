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

    private class Signature(val kind: String, val regex: Regex, val describe: (String) -> String)

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
        Signature("JWT", Regex("""\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b""")) {
            "Looks like a JWT (base64url header.payload.signature)"
        },
        Signature("PRIVATE_KEY", Regex("""-----BEGIN ((RSA|EC|OPENSSH|DSA|ENCRYPTED) )?PRIVATE KEY-----""")) {
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
    )

    private val SECRET_LIKE_NAME = Regex(
        """(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|private[_-]?key)""",
        RegexOption.IGNORE_CASE,
    )

    private val OBVIOUS_PLACEHOLDER = Regex(
        """^(|changeme|change[_-]?me|todo|fixme|xxx+|your[_-].*|placeholder|example|test|dummy|<.*>|\$\{.*})$""",
        RegexOption.IGNORE_CASE,
    )

    private const val MIN_ENTROPY_LENGTH = 12
    private const val MIN_ENTROPY_BITS_PER_CHAR = 3.3

    /** Only the exact-format signatures -- no name hint, no entropy guess. */
    fun scanSignatures(value: String): SecretFinding? {
        for (signature in SIGNATURES) {
            val match = signature.regex.find(value) ?: continue
            return SecretFinding(signature.kind, signature.describe(match.value))
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
