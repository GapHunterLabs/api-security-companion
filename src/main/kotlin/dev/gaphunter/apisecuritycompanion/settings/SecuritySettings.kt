package dev.gaphunter.apisecuritycompanion.settings

import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.components.service

/**
 * Every rule can be turned off — no exceptions, no "this check cannot be
 * disabled" the way Better Highlights' Cognitive Complexity or Qodana's
 * paywalled checks were reported to work. A disabled rule is fully
 * inert, not just hidden.
 *
 * Almost every rule is also ON by default (`disabledRuleIds`, an
 * opt-out set). [SecurityRule.ML_FALSE_POSITIVE_REDUCTION] is the one
 * deliberate exception — it SUPPRESSES a warning instead of only adding
 * one, so it defaults OFF and needs an explicit opt-in
 * (`enabledRuleIds`), even for a user with a valid Pro license. Old
 * `apiSecurityCompanion.xml` files from before this rule existed
 * deserialize with an empty `enabledRuleIds`, which is exactly the
 * correct "still off" state for existing users — no migration needed.
 */
@State(name = "ApiSecurityCompanionSettings", storages = [Storage("apiSecurityCompanion.xml")])
class SecuritySettings : PersistentStateComponent<SecuritySettings.State> {

    class State {
        var disabledRuleIds: MutableSet<String> = mutableSetOf()
        var enabledRuleIds: MutableSet<String> = mutableSetOf()
    }

    private var state = State()

    override fun getState(): State = state

    override fun loadState(state: State) {
        this.state = state
    }

    fun isEnabled(rule: SecurityRule): Boolean =
        if (rule.defaultEnabled) rule.id !in state.disabledRuleIds else rule.id in state.enabledRuleIds

    fun setEnabled(rule: SecurityRule, enabled: Boolean) {
        if (rule.defaultEnabled) {
            if (enabled) state.disabledRuleIds.remove(rule.id) else state.disabledRuleIds.add(rule.id)
        } else {
            if (enabled) state.enabledRuleIds.add(rule.id) else state.enabledRuleIds.remove(rule.id)
        }
    }

    companion object {
        fun getInstance(): SecuritySettings = service()
    }
}
