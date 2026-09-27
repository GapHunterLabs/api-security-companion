package dev.gaphunter.apisecuritycompanion.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigSecretScannerTest {

    // Assembled from pieces so no well-formed token sits in the source (see SecretSignaturesTest).
    private val openAiKey = "sk-" + "proj-" + "aB3dE9gH2jK5mN8pQ1sT4vW7yZ0cF6hJ9lO2rU5x".repeat(2)
    private val entropyValue = "Tt9!kQ2#mZp7@Lc4dW1&"

    private fun scan(value: String, key: String?, heuristic: Boolean = false, ancestors: List<String> = emptyList()) =
        ConfigSecretScanner.scanValue(value, ConfigContext(key, ancestors), heuristic)

    // ---------- exact formats are Free, whatever the key is called ----------

    @Test
    fun anExactFormatIsReportedWithoutTheHeuristic() {
        assertEquals("OPENAI_API_KEY", scan(openAiKey, "OPENAI_API_KEY", heuristic = false)?.kind)
        assertEquals("OPENAI_API_KEY", scan(openAiKey, "notes", heuristic = false)?.kind)
        assertEquals("OPENAI_API_KEY", scan(openAiKey, null, heuristic = false)?.kind)
    }

    @Test
    fun aTokenInsideALongerValueIsStillFound() {
        assertEquals("OPENAI_API_KEY", scan("Bearer $openAiKey", "Authorization")?.kind)
        assertEquals("OPENAI_API_KEY", scan("--api-key=$openAiKey", "args")?.kind)
    }

    // ---------- values that are not secrets ----------

    @Test
    fun referencesToAnEnvironmentVariableAreNeverFindings() {
        for (ref in listOf("\${OPENAI_API_KEY}", "\$OPENAI_API_KEY", "%OPENAI_API_KEY%", "{{ vault_openai_key }}", "<your-api-key>", "env:OPENAI_API_KEY")) {
            assertNull("reference $ref", scan(ref, "OPENAI_API_KEY", heuristic = true))
        }
    }

    @Test
    fun sampleDataUnderAnExampleKeyIsSkipped() {
        assertNull(scan(openAiKey, "value", ancestors = listOf("example")))
        assertNull(scan(openAiKey, "token", ancestors = listOf("examples", "components")))
        assertNull(scan(openAiKey, "description"))
    }

    @Test
    fun blankValuesAreSkipped() {
        assertNull(scan("", "password", heuristic = true))
        assertNull(scan("   ", "password", heuristic = true))
    }

    // ---------- the Pro heuristic ----------

    @Test
    fun theHeuristicIsOffUnlessEnabled() {
        assertNull(scan(entropyValue, "API_KEY", heuristic = false))
        assertEquals("GENERIC_HIGH_ENTROPY", scan(entropyValue, "API_KEY", heuristic = true)?.kind)
    }

    @Test
    fun theHeuristicNeedsAKeyThatNamesACredential() {
        assertEquals("GENERIC_HIGH_ENTROPY", scan(entropyValue, "client_secret", heuristic = true)?.kind)
        assertEquals("GENERIC_HIGH_ENTROPY", scan(entropyValue, "DB_PASSWORD", heuristic = true)?.kind)
        assertEquals("GENERIC_HIGH_ENTROPY", scan(entropyValue, "spring.datasource.password", heuristic = true)?.kind)
        assertEquals("GENERIC_HIGH_ENTROPY", scan(entropyValue, "githubToken", heuristic = true)?.kind)
        assertNull(scan(entropyValue, "greeting", heuristic = true))
        assertNull(scan(entropyValue, null, heuristic = true))
    }

    @Test
    fun settingsAboutASecretAreNotSecrets() {
        // The credential noun must be the LAST word: these are configuration ABOUT a secret.
        assertNull(scan(entropyValue, "token_url", heuristic = true))
        assertNull(scan(entropyValue, "secretName", heuristic = true))
        assertNull(scan(entropyValue, "passwordPolicy", heuristic = true))
        assertNull(scan(entropyValue, "tokenEndpoint", heuristic = true))
    }

    @Test
    fun urlsPathsSentencesAndWordsAreNotCredentialValues() {
        assertNull(scan("https://auth.example.com/oauth/token", "token", heuristic = true))
        assertNull(scan("/run/secrets/db_password_file", "password", heuristic = true))
        assertNull(scan("./secrets/service-account.json", "credentials", heuristic = true))
        assertNull(scan("the password is rotated every ninety days", "password", heuristic = true))
        assertNull(scan("authorization-code-grant-flow", "token", heuristic = true))
        assertNull(scan("changeme", "password", heuristic = true))
    }

    @Test
    fun aGeneratedKeyShapedLikeASlugButWithADigitRunStillCounts() {
        // Found by the corpus run: a slug guard that allowed digits hid this key.
        assertEquals("GENERIC_HIGH_ENTROPY", scan("acme_deploy_9f8e7d6c5b4a3210", "vault_deploy_api_key", heuristic = true)?.kind)
        assertNull(scan("GITHUB_TOKEN_NAME", "token", heuristic = true))
        assertNull(scan("authorization-code-grant-flow", "token", heuristic = true))
    }

    @Test
    fun aUrlWithEmbeddedCredentialsStillCounts() {
        assertNotNull(scan("postgres://app:Tt9!kQ2#mZp7@db.internal:5432/orders", "url_password", heuristic = true))
    }

    @Test
    fun theHeuristicSeesThroughAnAuthSchemeAndACommandLineFlag() {
        assertEquals("GENERIC_HIGH_ENTROPY", scan("Bearer $entropyValue", "Authorization", heuristic = true)?.kind)
        assertEquals("GENERIC_HIGH_ENTROPY", scan("--api-key=$entropyValue", "args", heuristic = true)?.kind)
        assertNull(scan("--port=8080", "args", heuristic = true))
        assertNull(scan("--token-url=https://auth.example.com/token", "args", heuristic = true))
    }

    @Test
    fun aReferenceAfterAnAuthSchemeIsNotACredential() {
        assertNull(scan("Bearer \${GITHUB_TOKEN}", "Authorization", heuristic = true))
    }

    // ---------- key naming ----------

    @Test
    fun credentialKeyNames() {
        for (name in listOf("password", "DB_PASSWORD", "api_key", "apiKey", "OPENAI_API_KEY", "client_secret", "access-token", "githubToken", "Authorization", "auth", "private_key")) {
            assertTrue(name, ConfigSecretScanner.isCredentialKey(name))
        }
        for (name in listOf("token_url", "secretName", "passwordPolicy", "primary_key", "sort_key", "author", "keyboard", "tokenizer")) {
            assertFalse(name, ConfigSecretScanner.isCredentialKey(name))
        }
    }

    // ---------- .env ----------

    @Test
    fun dotEnvValuesAreFoundWithTheirExactOffsets() {
        val text = "# comment\r\nA=1\r\nexport OPENAI_API_KEY=\"$openAiKey\"\r\nQUOTED='$openAiKey'\nBARE=$openAiKey # trailing\n"
        val hits = ConfigSecretScanner.scanDotEnv(text, heuristicEnabled = false)
        assertEquals(3, hits.size)
        for (hit in hits) assertEquals(openAiKey, text.substring(hit.start, hit.end))
    }

    @Test
    fun dotEnvSkipsCommentsBlankLinesAndReferences() {
        val text = "\n# OPENAI_API_KEY=$openAiKey\n\nOPENAI_API_KEY=\${OPENAI_API_KEY}\nNAME=demo\n"
        assertTrue(ConfigSecretScanner.scanDotEnv(text, heuristicEnabled = true).isEmpty())
    }

    @Test
    fun dotEnvHeuristicIsGatedToo() {
        val text = "DB_PASSWORD=$entropyValue\n"
        assertTrue(ConfigSecretScanner.scanDotEnv(text, heuristicEnabled = false).isEmpty())
        val hits = ConfigSecretScanner.scanDotEnv(text, heuristicEnabled = true)
        assertEquals(1, hits.size)
        assertEquals(entropyValue, text.substring(hits[0].start, hits[0].end))
    }

    // ---------- which files ----------

    @Test
    fun templateAndGeneratedFilesAreSkipped() {
        for (name in listOf(".env.example", ".env.sample", "config.sample.json", "application.properties.template", "package-lock.json", "pnpm-lock.yaml", "google-services.json")) {
            assertTrue(name, ConfigSecretScanner.isTemplateOrGeneratedFile(name))
        }
        for (name in listOf(".env", ".env.local", "mcp.json", "application.yml", "docker-compose.yaml", "examples.json")) {
            assertFalse(name, ConfigSecretScanner.isTemplateOrGeneratedFile(name))
        }
    }

    @Test
    fun buildOutputAndDependencyDirectoriesAreSkipped() {
        assertTrue(ConfigSecretScanner.isInSkippedDirectory("C:\\work\\app\\node_modules\\pkg\\config.json"))
        assertTrue(ConfigSecretScanner.isInSkippedDirectory("/work/app/build/resources/main/application.yml"))
        assertFalse(ConfigSecretScanner.isInSkippedDirectory("/work/app/src/main/resources/application.yml"))
        assertFalse(ConfigSecretScanner.isInSkippedDirectory("/work/output-service/config.json"))
    }

    @Test
    fun mcpConfigFilesAreRecognizedByName() {
        for (path in listOf("/p/.cursor/mcp.json", "C:\\Users\\a\\.mcp.json", "/x/claude_desktop_config.json", "/p/.vscode/mcp.json")) {
            assertTrue(path, ConfigSecretScanner.isMcpConfig(path))
        }
        assertFalse(ConfigSecretScanner.isMcpConfig("/p/package.json"))
    }
}
