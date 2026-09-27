package dev.gaphunter.apisecuritycompanion.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The exact-format signatures added for AI-service and developer-platform tokens.
 * Every fake token is assembled from pieces, never written as one literal: GitHub's
 * push protection flags a well-formed token in a source file even when it is fake.
 */
class SecretSignaturesTest {

    private companion object {
        const val ALNUM = "aB3dE9gH2jK5mN8pQ1sT4vW7yZ0cF6hJ9lO2rU5xC8"
        const val HEX = "0123456789abcdef"

        /** Deterministic body of exactly [n] characters drawn from [alphabet]. */
        fun body(n: Int, alphabet: String = ALNUM): String = (0 until n).map { alphabet[(it * 7 + 3) % alphabet.length] }.joinToString("")
    }

    private fun kind(value: String) = SecretDetector.scanLiteral(value)?.kind

    @Test
    fun detectsOpenAiProjectKeys() {
        assertEquals("OPENAI_API_KEY", kind("sk-" + "proj-" + body(80)))
        assertEquals("OPENAI_API_KEY", kind("sk-" + "svcacct-" + body(60)))
        assertEquals("OPENAI_API_KEY", kind("OPENAI_API_KEY=sk-" + "admin-" + body(50)))
    }

    @Test
    fun detectsTheOlderOpenAiShape() {
        assertEquals("OPENAI_API_KEY", kind("sk-" + body(20) + "T3Blbk" + "FJ" + body(20)))
    }

    @Test
    fun doesNotFlagAShortOrUnrelatedSkPrefix() {
        assertNull(kind("sk-proj-" + body(10)))
        assertNull(kind("sk-learn-is-a-python-library-name"))
        assertNull(kind("task-1234567890abcdefghij"))
    }

    @Test
    fun detectsAnthropicKeys() {
        assertEquals("ANTHROPIC_API_KEY", kind("sk-" + "ant-" + "api03-" + body(93) + "AA"))
        assertEquals("ANTHROPIC_API_KEY", kind("sk-" + "ant-" + "admin01-" + body(90)))
        assertNull(kind("sk-" + "ant-" + "api03-" + body(20)))
    }

    @Test
    fun detectsHuggingFaceTokensButOnlyTheRealShape() {
        assertEquals("HUGGINGFACE_TOKEN", kind("hf_" + body(34, "abcdefghijklmnopqrstuvwxyzABCDEFGH")))
        assertEquals("HUGGINGFACE_TOKEN", kind("api_org_" + body(34, "abcdefghijklmnopqrstuvwxyz")))
        assertNull(kind("hf_" + body(33, "abcdefghijklmnopqrstuvwxyz")))
        assertNull(kind("hf_" + body(34, "abcdefghijklmnopqrstuvwxyz").replaceRange(5, 6, "7")))
    }

    @Test
    fun detectsGroqAndPerplexityKeys() {
        assertEquals("GROQ_API_KEY", kind("gsk_" + body(52)))
        assertEquals("PERPLEXITY_API_KEY", kind("pplx-" + body(48)))
        assertNull(kind("gsk_" + body(20)))
    }

    @Test
    fun detectsGoogleApiKeysIncludingOnesEndingInAHyphen() {
        assertEquals("GOOGLE_API_KEY", kind("AIza" + body(35)))
        assertEquals("GOOGLE_API_KEY", kind("AIza" + body(34) + "-"))
        assertNull(kind("AIza" + body(20)))
    }

    @Test
    fun detectsGitHubFineGrainedTokens() {
        assertEquals("GITHUB_FINE_GRAINED_TOKEN", kind("github_" + "pat_" + body(82)))
        assertNull(kind("github_" + "pat_" + body(20)))
    }

    @Test
    fun detectsGitLabAndNpmAndPyPiTokens() {
        assertEquals("GITLAB_TOKEN", kind("glpat" + "-" + body(20)))
        assertEquals("NPM_TOKEN", kind("npm_" + body(36)))
        assertEquals("PYPI_TOKEN", kind("pypi-" + "AgEIcHlwaS5vcmc" + body(70)))
        assertNull(kind("npm_" + body(10)))
    }

    @Test
    fun detectsSendGridShopifyDigitalOceanDatabricksAndVaultTokens() {
        assertEquals("SENDGRID_API_KEY", kind("SG." + body(22) + "." + body(43)))
        assertEquals("SHOPIFY_TOKEN", kind("shp" + "at_" + body(32, HEX)))
        assertEquals("DIGITALOCEAN_TOKEN", kind("dop_" + "v1_" + body(64, HEX)))
        assertEquals("DATABRICKS_TOKEN", kind("dapi" + body(32, HEX)))
        assertEquals("VAULT_TOKEN", kind("hvs." + body(95)))
        assertNull(kind("dapi" + body(10, HEX)))
    }

    @Test
    fun detectsSlackWebhookUrls() {
        val url = "https://hooks.slack.com/services/" + "T" + "0".repeat(8) + "/B" + "0".repeat(8) + "/" + body(24)
        assertEquals("SLACK_WEBHOOK", kind(url))
        assertNull(kind("https://hooks.slack.com/services/"))
    }

    @Test
    fun theOlderSignaturesKeepTheirOrderAndMessages() {
        // Stripe was the last of the original six; a string matching two formats reports the earlier one.
        assertEquals("AWS_ACCESS_KEY", kind("AKIA" + "IOSFODNN7EXAMPLE"))
        assertEquals("Looks like an AWS access key ID (AKIAIOSF...)", SecretDetector.scanLiteral("AKIA" + "IOSFODNN7EXAMPLE")?.description)
        assertEquals("Looks like a Stripe secret/restricted API key (sk_live_4eC...)", SecretDetector.scanLiteral("sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc")?.description)
    }

    @Test
    fun aFindingNeverContainsTheWholeToken() {
        val token = "sk-" + "proj-" + body(80)
        val description = SecretDetector.scanLiteral(token)!!.description
        assert(token !in description) { "the warning text must not echo the full secret: $description" }
    }
}
