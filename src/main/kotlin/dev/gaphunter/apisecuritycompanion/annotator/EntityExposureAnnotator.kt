package dev.gaphunter.apisecuritycompanion.annotator

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.Annotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.psi.PsiClassType
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiMethod
import dev.gaphunter.apisecuritycompanion.detect.ExcessiveExposureDetector
import dev.gaphunter.apisecuritycompanion.review.ReviewPrompt
import dev.gaphunter.apisecuritycompanion.settings.SecurityRule
import dev.gaphunter.apisecuritycompanion.settings.SecuritySettings

/**
 * Java-only for v0.1 — Kotlin's annotation PSI (`KtAnnotationEntry`)
 * needs its own resolution path that isn't worth rushing for the first
 * release. Documented as a known gap in README rather than a silent
 * omission.
 */
class EntityExposureAnnotator : Annotator {

    override fun annotate(element: PsiElement, holder: AnnotationHolder) {
        if (element !is PsiMethod) return
        val settings = SecuritySettings.getInstance()
        val exposureOn = settings.isEnabled(SecurityRule.EXCESSIVE_DATA_EXPOSURE)
        val massAssignmentOn = settings.isEnabled(SecurityRule.MASS_ASSIGNMENT)
        if (!exposureOn && !massAssignmentOn) return

        val methodAnnotations = element.annotations.mapNotNull { it.nameReferenceElement?.referenceName }.toSet()
        if (methodAnnotations.isEmpty()) return

        if (exposureOn) {
            val returnAnnotations = ((element.returnType as? PsiClassType)?.resolve())
                ?.annotations?.mapNotNull { it.nameReferenceElement?.referenceName }?.toSet() ?: emptySet()
            if (ExcessiveExposureDetector.isExposingEntityDirectly(methodAnnotations, returnAnnotations)) {
                holder.newAnnotation(
                    HighlightSeverity.WARNING,
                    "This endpoint returns a persistence entity directly — every field on it, including ones never meant to be public, gets serialized to every caller",
                ).range(element.nameIdentifier?.textRange ?: element.textRange).create()

                val file = element.containingFile
                val anchor = element.nameIdentifier ?: element
                val path = file.virtualFile?.path
                if (path != null) {
                    val lineNumber = file.viewProvider.document?.getLineNumber(anchor.textRange.startOffset) ?: -1
                    ReviewPrompt.recordHit(file.project, "$path:$lineNumber:exposure")
                }
            }
        }

        if (massAssignmentOn) {
            for (parameter in element.parameterList.parameters) {
                val paramAnnotations = ((parameter.type as? PsiClassType)?.resolve())
                    ?.annotations?.mapNotNull { it.nameReferenceElement?.referenceName }?.toSet() ?: emptySet()
                if (ExcessiveExposureDetector.isMassAssignmentRisk(methodAnnotations, paramAnnotations)) {
                    holder.newAnnotation(
                        HighlightSeverity.WARNING,
                        "This write endpoint binds the request body directly onto a persistence entity — a client can set any column, including ones like 'isAdmin' that were never meant to be client-writable",
                    ).range(parameter.textRange).create()

                    val file = parameter.containingFile
                    val path = file.virtualFile?.path
                    if (path != null) {
                        val lineNumber = file.viewProvider.document?.getLineNumber(parameter.textRange.startOffset) ?: -1
                        ReviewPrompt.recordHit(file.project, "$path:$lineNumber:mass-assignment")
                    }
                }
            }
        }
    }
}
