package dev.gaphunter.apisecuritycompanion.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RuleGateTest {
    private val bola = SecurityRule.BROKEN_OBJECT_LEVEL_AUTH
    private val secrets = SecurityRule.SECRET_DETECTION
    private val ml = SecurityRule.ML_FALSE_POSITIVE_REDUCTION

    private fun decide(
        rule: SecurityRule,
        licensed: Boolean,
        teamRuleIds: Set<String> = emptySet(),
        enabledLocally: Boolean = true,
        proCoverage: Boolean = rule.isPro,
    ) = RuleGate.decide(rule, proCoverage, licensed, teamRuleIds, enabledLocally)

    @Test
    fun `a team rules file never unlocks a Pro rule without a license`() {
        assertFalse(decide(bola, licensed = false, teamRuleIds = setOf(bola.id)))
    }

    @Test
    fun `the Kotlin path of a free rule is Pro coverage and needs a license even when the file lists it`() {
        val exposure = SecurityRule.EXCESSIVE_DATA_EXPOSURE
        assertFalse(decide(exposure, licensed = false, teamRuleIds = setOf(exposure.id), proCoverage = true))
        assertTrue(decide(exposure, licensed = true, proCoverage = true))
    }

    @Test
    fun `a licensed member keeps a team rule on after turning it off locally`() {
        assertTrue(decide(bola, licensed = true, teamRuleIds = setOf(bola.id), enabledLocally = false))
        assertTrue(decide(secrets, licensed = true, teamRuleIds = setOf(secrets.id), enabledLocally = false))
    }

    @Test
    fun `without a license the team file changes nothing for a free rule`() {
        assertFalse(decide(secrets, licensed = false, teamRuleIds = setOf(secrets.id), enabledLocally = false))
        assertTrue(decide(secrets, licensed = false, teamRuleIds = setOf(secrets.id), enabledLocally = true))
    }

    @Test
    fun `a rule the file doesn't list follows the local setting`() {
        assertFalse(decide(bola, licensed = true, teamRuleIds = setOf(secrets.id), enabledLocally = false))
        assertTrue(decide(bola, licensed = true, enabledLocally = true))
    }

    @Test
    fun `the ML filter can't be switched on by the team file`() {
        assertFalse(decide(ml, licensed = true, teamRuleIds = setOf(ml.id), enabledLocally = false))
        assertTrue(decide(ml, licensed = true, enabledLocally = true))
        assertFalse(decide(ml, licensed = false, enabledLocally = true))
    }

    @Test
    fun `free rules run without a license`() {
        assertTrue(decide(secrets, licensed = false))
    }

    @Test
    fun `exactly the paid rules are marked Pro`() {
        assertEquals(
            setOf("configSecretHeuristic", "brokenObjectLevelAuth", "unrestrictedResourceConsumption", "mlFalsePositiveReduction"),
            SecurityRule.entries.filter { it.isPro }.map { it.id }.toSet(),
        )
    }
}
