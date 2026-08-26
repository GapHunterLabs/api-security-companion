package dev.gaphunter.apisecuritycompanion.annotator

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.Annotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.psi.PsiClass
import com.intellij.psi.PsiElement
import dev.gaphunter.apisecuritycompanion.detect.InsecureTransportDetector
import dev.gaphunter.apisecuritycompanion.review.ReviewPrompt
import dev.gaphunter.apisecuritycompanion.settings.SecurityRule
import dev.gaphunter.apisecuritycompanion.settings.SecuritySettings
import org.jetbrains.kotlin.psi.KtClass

/**
 * Flags the classic "accept every TLS certificate" anti-pattern
 * (CWE-295). Works off the class's own source text via
 * [InsecureTransportDetector.scanTrustManagerBody], which is why one
 * annotator handles both Java's `PsiClass` and Kotlin's `KtClass` —
 * `.text` means the same thing on both.
 */
class TrustManagerAnnotator : Annotator {

    override fun annotate(element: PsiElement, holder: AnnotationHolder) {
        if (!SecuritySettings.getInstance().isEnabled(SecurityRule.TRUST_ALL_CERTIFICATES)) return

        val classText = when (element) {
            is PsiClass -> element.text
            is KtClass -> element.text
            else -> return
        }

        InsecureTransportDetector.scanTrustManagerBody(classText)?.let { finding ->
            val nameElement = when (element) {
                is PsiClass -> element.nameIdentifier ?: element
                is KtClass -> element.nameIdentifier ?: element
                else -> element
            }
            holder.newAnnotation(HighlightSeverity.WARNING, finding.description)
                .range(nameElement.textRange)
                .create()

            val file = element.containingFile
            val path = file.virtualFile?.path
            if (path != null) {
                val lineNumber = file.viewProvider.document?.getLineNumber(nameElement.textRange.startOffset) ?: -1
                ReviewPrompt.recordHit(file.project, "$path:$lineNumber")
            }
        }
    }
}
