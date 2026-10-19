package dev.gaphunter.apisecuritycompanion.settings

import com.intellij.openapi.project.Project
import dev.gaphunter.apisecuritycompanion.licensing.CheckLicense

/**
 * The one place that decides whether a check runs, shared by every annotator:
 *
 * - Pro coverage needs a valid license. That includes the Kotlin path of the two
 *   free OWASP rules, which is why callers can pass [proCoverage] explicitly.
 * - The project's `.gaphunter-security-rules` file (see [TeamPolicyLoader]) is a Pro
 *   feature: for a licensed member, every rule it lists stays on even after a local
 *   opt-out in Settings. Without a license the file changes nothing.
 * - Otherwise the user's own Settings decide.
 */
object RuleGate {

    fun isActive(project: Project, rule: SecurityRule, proCoverage: Boolean = rule.isPro): Boolean {
        val teamRuleIds = TeamPolicyLoader.forcedRuleIds(project)
        // LicensingFacade lookups aren't free, so only pay for one when the answer depends on it.
        val licenseMatters = proCoverage || (rule.teamEnforceable && rule.id in teamRuleIds)
        val licensed = licenseMatters && CheckLicense.isLicensed() == true
        return decide(rule, proCoverage, licensed, teamRuleIds, SecuritySettings.getInstance().isEnabled(rule))
    }

    /** The decision itself, without the platform lookups, so it can be tested directly. */
    fun decide(
        rule: SecurityRule,
        proCoverage: Boolean,
        licensed: Boolean,
        teamRuleIds: Set<String>,
        enabledLocally: Boolean,
    ): Boolean {
        if (proCoverage && !licensed) return false
        if (licensed && rule.teamEnforceable && rule.id in teamRuleIds) return true
        return enabledLocally
    }
}
