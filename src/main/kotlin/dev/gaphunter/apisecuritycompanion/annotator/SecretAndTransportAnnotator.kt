package dev.gaphunter.apisecuritycompanion.annotator

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.Annotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiLiteralExpression
import com.intellij.psi.PsiLiteralValue
import com.intellij.psi.PsiLocalVariable
import com.intellij.psi.PsiField
import com.intellij.psi.PsiAssignmentExpression
import com.intellij.psi.PsiReferenceExpression
import dev.gaphunter.apisecuritycompanion.detect.InsecureTransportDetector
import dev.gaphunter.apisecuritycompanion.detect.SecretDetector
import dev.gaphunter.apisecuritycompanion.detect.ml.MlClassifierService
import dev.gaphunter.apisecuritycompanion.review.ReviewPrompt
import dev.gaphunter.apisecuritycompanion.settings.RuleGate
import dev.gaphunter.apisecuritycompanion.settings.SecurityRule
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
        // Read before the smart cast below: after it, the compiler can type the
        // call through an experimental interface both branches share.
        val project = element.project
        val (value, variableHint) = when (element) {
            is PsiLiteralValue -> {
                val v = element.value as? String ?: return
                v to (element as? PsiLiteralExpression)?.let { javaVariableNameHint(it) }
            }
            is KtStringTemplateExpression -> {
                if (element.hasInterpolation()) return
                val v = element.entries.joinToString("") { it.text }
                v to kotlinVariableNameHint(element)
            }
            else -> return
        }

        // Gated after the literal check: annotate() runs for every element in the file.
        val secretsOn = RuleGate.isActive(project, SecurityRule.SECRET_DETECTION)
        val httpOn = RuleGate.isActive(project, SecurityRule.INSECURE_HTTP)
        if (!secretsOn && !httpOn) return

        val range: TextRange = element.getTextRange()

        if (secretsOn) {
            SecretDetector.scanLiteral(value, variableHint)?.let { finding ->
                if (finding.kind == "GENERIC_HIGH_ENTROPY" && isMlFalsePositiveReductionActive(project)) {
                    if (MlClassifierService.getInstance().isConfidentFalsePositive(value)) return@let
                }
                holder.newAnnotation(HighlightSeverity.WARNING, "Potential secret: ${finding.description}")
                    .range(range)
                    .create()
                recordHitFor(element, "secret")
                return
            }
        }
        if (httpOn) {
            InsecureTransportDetector.scanUrlLiteral(value)?.let { finding ->
                holder.newAnnotation(HighlightSeverity.WARNING, finding.description)
                    .range(range)
                    .create()
                recordHitFor(element, "insecure-http")
            }
        }
    }

    /**
     * Pro-gated, and off by default even with a license (see
     * [SecurityRule.ML_FALSE_POSITIVE_REDUCTION] for why this one rule
     * doesn't follow the rest of the file's Free/no-license pattern).
     * Every other check in this class stays exactly as before --
     * secret-by-signature detection and insecure-HTTP detection are
     * still fully Free, ungated, unaffected by licensing either way.
     *
     * The team rules file can't switch it on ([SecurityRule.teamEnforceable]):
     * that file keeps an org-agreed rule ON for every licensed member, but
     * this rule SUPPRESSES warnings, so silently force-enabling it via a
     * committed policy file would be the opposite of the "opt in after
     * you understand what this does" design goal.
     */
    private fun isMlFalsePositiveReductionActive(project: Project): Boolean =
        RuleGate.isActive(project, SecurityRule.ML_FALSE_POSITIVE_REDUCTION)

    private fun recordHitFor(element: PsiElement, kind: String) {
        val file = element.containingFile
        val path = file.virtualFile?.path ?: return
        val lineNumber = file.viewProvider.document?.getLineNumber(element.textRange.startOffset) ?: -1
        ReviewPrompt.recordHit(file.project, "$path:$lineNumber:$kind")
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
