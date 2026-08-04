package dev.gaphunter.apisecuritycompanion.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TeamPolicyLoaderTest {
    @Test
    fun `parses one rule id per line`() {
        val text = "secretDetection\ninsecureHttp\nbrokenObjectLevelAuth"
        assertEquals(setOf("secretDetection", "insecureHttp", "brokenObjectLevelAuth"), TeamPolicyLoader.parseRuleIds(text))
    }

    @Test
    fun `ignores comments and blank lines`() {
        val text = """
            # Team-enforced rules
            secretDetection

            # require these too
            trustAllCertificates
        """.trimIndent()
        assertEquals(setOf("secretDetection", "trustAllCertificates"), TeamPolicyLoader.parseRuleIds(text))
    }

    @Test
    fun `strips inline comments after a rule id`() {
        val text = "secretDetection # required by security team"
        assertEquals(setOf("secretDetection"), TeamPolicyLoader.parseRuleIds(text))
    }

    @Test
    fun `empty file produces no forced rules, never throws`() {
        assertTrue(TeamPolicyLoader.parseRuleIds("").isEmpty())
        assertTrue(TeamPolicyLoader.parseRuleIds("   \n  \n").isEmpty())
    }
}
