package dev.gaphunter.apisecuritycompanion.settings

import com.intellij.openapi.options.Configurable
import com.intellij.ui.components.JBCheckBox
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.BoxLayout

class SecuritySettingsConfigurable : Configurable {

    private val checkboxes = SecurityRule.entries.associateWith { JBCheckBox(it.displayName) }
    private var panel: JPanel? = null

    override fun getDisplayName(): String = "API Security Companion"

    override fun createComponent(): JComponent {
        val settings = SecuritySettings.getInstance()
        val newPanel = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }
        for (rule in SecurityRule.entries) {
            val checkbox = checkboxes.getValue(rule)
            checkbox.isSelected = settings.isEnabled(rule)
            newPanel.add(checkbox)
        }
        panel = newPanel
        return newPanel
    }

    override fun isModified(): Boolean {
        val settings = SecuritySettings.getInstance()
        return SecurityRule.entries.any { checkboxes.getValue(it).isSelected != settings.isEnabled(it) }
    }

    override fun apply() {
        val settings = SecuritySettings.getInstance()
        for (rule in SecurityRule.entries) {
            settings.setEnabled(rule, checkboxes.getValue(rule).isSelected)
        }
    }

    override fun reset() {
        val settings = SecuritySettings.getInstance()
        for (rule in SecurityRule.entries) {
            checkboxes.getValue(rule).isSelected = settings.isEnabled(rule)
        }
    }
}
