package dev.gaphunter.apisecuritycompanion.settings

import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.components.service

/**
 * Every rule is on by default and every rule can be turned off — no
 * exceptions, no "this check cannot be disabled" the way Better
 * Highlights' Cognitive Complexity or Qodana's paywalled checks were
 * reported to work. A disabled rule is fully inert, not just hidden.
 */
@State(name = "ApiSecurityCompanionSettings", storages = [Storage("apiSecurityCompanion.xml")])
class SecuritySettings : PersistentStateComponent<SecuritySettings.State> {

    class State {
        var disabledRuleIds: MutableSet<String> = mutableSetOf()
    }

    private var state = State()

    override fun getState(): State = state

    override fun loadState(state: State) {
        this.state = state
    }

    fun isEnabled(rule: SecurityRule): Boolean = rule.id !in state.disabledRuleIds

    fun setEnabled(rule: SecurityRule, enabled: Boolean) {
        if (enabled) state.disabledRuleIds.remove(rule.id) else state.disabledRuleIds.add(rule.id)
    }

    companion object {
        fun getInstance(): SecuritySettings = service()
    }
}
