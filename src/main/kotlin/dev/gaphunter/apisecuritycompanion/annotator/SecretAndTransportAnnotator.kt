package dev.gaphunter.apisecuritycompanion.annotator

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.Annotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiLiteralExpression
import com.intellij.psi.PsiLocalVariable
import com.intellij.psi.PsiField
import com.intellij.psi.PsiAssignmentExpression
import com.intellij.psi.PsiReferenceExpression
import dev.gaphunter.apisecuritycompanion.detect.InsecureTransportDetector
import dev.gaphunter.apisecuritycompanion.detect.SecretDetector
import dev.gaphunter.apisecuritycompanion.settings.SecurityRule
import dev.gaphunter.apisecuritycompanion.settings.SecuritySettings
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * Scans string literals in Java and Kotlin source for hardcoded secrets
 * and plaintext-HTTP URLs. Runs as a normal `Annotator`, which the
 * platform's own highlighting daemon already schedules off the EDT — no
 * extra threading needed for a check this cheap (a handful of regexes
 * per literal).
 */
class SecretAndTransportAnnotator : Annotator {

    override fun annotate(element: PsiElement, holder: AnnotationHolder) {
        val settings = SecuritySettings.getInstance()
        val secretsOn = settings.isEnabled(SecurityRule.SECRET_DETECTION)
        val httpOn = settings.isEnabled(SecurityRule.INSECURE_HTTP)
        if (!secretsOn && !httpOn) return

        val (value, variableHint) = when (element) {
            is PsiLiteralExpression -> {
                val v = element.value as? String ?: return
                v to javaVariableNameHint(element)
            }
            is KtStringTemplateExpression -> {
                if (element.hasInterpolation()) return
                val v = element.entries.joinToString("") { it.text }
                v to kotlinVariableNameHint(element)
            }
            else -> return
        }

        if (secretsOn) {
            SecretDetector.scanLiteral(value, variableHint)?.let { finding ->
                holder.newAnnotation(HighlightSeverity.WARNING, "Potential secret: ${finding.description}")
                    .range(element.textRange)
                    .create()
                return
            }
        }
        if (httpOn) {
            InsecureTransportDetector.scanUrlLiteral(value)?.let { finding ->
                holder.newAnnotation(HighlightSeverity.WARNING, finding.description)
                    .range(element.textRange)
                    .create()
            }
        }
    }

    private fun javaVariableNameHint(literal: PsiLiteralExpression): String? {
        val parent = literal.parent
        return when (parent) {
            is PsiLocalVariable -> parent.name
            is PsiField -> parent.name
            is PsiAssignmentExpression -> (parent.lExpression as? PsiReferenceExpression)?.referenceName
            else -> null
        }
    }

    private fun kotlinVariableNameHint(literal: KtStringTemplateExpression): String? {
        val property = literal.parent as? KtProperty
        return property?.name
    }
}
