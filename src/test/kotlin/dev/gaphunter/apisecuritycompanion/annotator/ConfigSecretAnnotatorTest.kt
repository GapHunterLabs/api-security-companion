package dev.gaphunter.apisecuritycompanion.annotator

import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.testFramework.fixtures.BasePlatformTestCase
import dev.gaphunter.apisecuritycompanion.settings.SecurityRule
import dev.gaphunter.apisecuritycompanion.settings.SecuritySettings

/** The configuration-file scan through the real platform pipeline (JSON, YAML, .properties, .env). */
class ConfigSecretAnnotatorTest : BasePlatformTestCase() {

    // Assembled from pieces: a well-formed token in the source would trip GitHub's push protection.
    private val openAiKey = "sk-" + "proj-" + "aB3dE9gH2jK5mN8pQ1sT4vW7yZ0cF6hJ9lO2rU5x".repeat(2)
    private val entropyValue = "Tt9!kQ2#mZp7@Lc4dW1&"

    override fun tearDown() {
        try {
            val settings = SecuritySettings.getInstance()
            settings.setEnabled(SecurityRule.CONFIG_FILE_SECRETS, true)
            settings.setEnabled(SecurityRule.SECRET_DETECTION, true)
            ConfigSecretAnnotator.forceHeuristicForTests = null
        } finally {
            super.tearDown()
        }
    }

    private fun secretWarnings(fileName: String, text: String): List<String> {
        myFixture.configureByText(fileName, text)
        return myFixture.doHighlighting()
            .filter { it.severity == HighlightSeverity.WARNING && it.description?.startsWith("Potential secret") == true }
            .map { it.description }
    }

    fun testMcpJsonFlagsAKnownTokenInEnv() {
        val warnings = secretWarnings(
            "mcp.json",
            """{"mcpServers": {"search": {"command": "npx", "args": ["-y", "search-mcp"], "env": {"OPENAI_API_KEY": "$openAiKey"}}}}""",
        )
        assertEquals(warnings.toString(), 1, warnings.size)
        assertTrue(warnings[0], warnings[0].contains("OpenAI API key"))
        assertTrue("MCP configs get the MCP-specific advice: ${warnings[0]}", warnings[0].contains("MCP server configs"))
    }

    fun testMcpJsonFlagsATokenPassedAsACommandLineArgument() {
        val warnings = secretWarnings("mcp.json", """{"mcpServers": {"s": {"command": "srv", "args": ["--api-key=$openAiKey"]}}}""")
        assertEquals(warnings.toString(), 1, warnings.size)
    }

    fun testAJsonKeyIsNeverTheFinding() {
        assertEquals(emptyList<String>(), secretWarnings("settings.json", """{"$openAiKey": "value"}"""))
    }

    fun testAnEnvironmentReferenceInAnMcpConfigIsFine() {
        val warnings = secretWarnings("mcp.json", """{"mcpServers": {"s": {"env": {"OPENAI_API_KEY": "${'$'}{OPENAI_API_KEY}"}}}}""")
        assertEquals(emptyList<String>(), warnings)
    }

    fun testYamlFlagsAKnownToken() {
        val warnings = secretWarnings("application.yml", "ai:\n  provider:\n    api-key: $openAiKey\n")
        assertEquals(warnings.toString(), 1, warnings.size)
        assertTrue(warnings[0], warnings[0].contains("environment variable or a secret store"))
    }

    fun testYamlSampleTokensInAnOpenApiExampleAreNotFlagged() {
        val yaml = "openapi: 3.1.0\ncomponents:\n  schemas:\n    Key:\n      type: string\n      example: $openAiKey\n"
        assertEquals(emptyList<String>(), secretWarnings("openapi.yaml", yaml))
    }

    fun testPropertiesFlagsAKnownToken() {
        val warnings = secretWarnings("application.properties", "spring.ai.openai.api-key=$openAiKey\nserver.port=8080\n")
        assertEquals(warnings.toString(), 1, warnings.size)
    }

    fun testDotEnvFlagsAKnownToken() {
        val warnings = secretWarnings(".env", "PORT=8080\nOPENAI_API_KEY=$openAiKey\n")
        assertEquals("language of .env is ${myFixture.file.language}: $warnings", 1, warnings.size)
    }

    fun testTemplateAndLockFilesAreSkipped() {
        assertEquals(emptyList<String>(), secretWarnings(".env.example", "OPENAI_API_KEY=$openAiKey\n"))
        assertEquals(emptyList<String>(), secretWarnings("package-lock.json", """{"token": "$openAiKey"}"""))
    }

    fun testTheEntropyHeuristicIsProOnly() {
        // No license in the test IDE: only exact formats are reported, never a guess.
        assertEquals(emptyList<String>(), secretWarnings("application.yml", "db:\n  password: $entropyValue\n"))
        assertEquals(emptyList<String>(), secretWarnings("app.properties", "db.password=$entropyValue\n"))
        assertEquals(emptyList<String>(), secretWarnings(".env", "DB_PASSWORD=$entropyValue\n"))
    }

    fun testTheEntropyHeuristicReportsWhenProIsActive() {
        ConfigSecretAnnotator.forceHeuristicForTests = true
        assertEquals(1, secretWarnings("application.yml", "db:\n  password: $entropyValue\n").size)
        assertEquals(1, secretWarnings("app.properties", "db.password=$entropyValue\n").size)
        assertEquals(1, secretWarnings(".env", "DB_PASSWORD=$entropyValue\n").size)
        assertEquals(1, secretWarnings("mcp.json", """{"mcpServers": {"s": {"headers": {"Authorization": "Bearer $entropyValue"}}}}""").size)
    }

    fun testTheProHeuristicStillSkipsSettingsAboutASecret() {
        ConfigSecretAnnotator.forceHeuristicForTests = true
        val yaml = "oauth:\n  token_url: https://auth.example.com/oauth/token\n  secretName: db-credentials\n  password: changeme\n"
        assertEquals(emptyList<String>(), secretWarnings("application.yml", yaml))
    }

    fun testTurningTheRuleOffSilencesIt() {
        SecuritySettings.getInstance().setEnabled(SecurityRule.CONFIG_FILE_SECRETS, false)
        assertEquals(emptyList<String>(), secretWarnings("mcp.json", """{"env": {"OPENAI_API_KEY": "$openAiKey"}}"""))
    }

    fun testTheMasterSecretRuleAlsoSilencesIt() {
        SecuritySettings.getInstance().setEnabled(SecurityRule.SECRET_DETECTION, false)
        assertEquals(emptyList<String>(), secretWarnings("application.yml", "key: $openAiKey\n"))
    }
}
