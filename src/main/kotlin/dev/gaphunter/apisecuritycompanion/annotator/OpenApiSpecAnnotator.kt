package dev.gaphunter.apisecuritycompanion.annotator

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.Annotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import dev.gaphunter.apisecuritycompanion.detect.OpenApiSpecDetector
import dev.gaphunter.apisecuritycompanion.settings.SecurityRule
import dev.gaphunter.apisecuritycompanion.settings.SecuritySettings

private val SPEC_MARKER = Regex("""^(openapi|swagger)\s*:\s*['"]?\d""", RegexOption.MULTILINE)

/**
 * Fires once per file (on the file's root PSI element, not per-token)
 * since both checks here need the whole document's text, not a single
 * element. Only activates on files whose content actually looks like an
 * OpenAPI/Swagger spec (`openapi: 3.x` / `swagger: 2.x`) — never on every
 * YAML or JSON file in the project.
 */
class OpenApiSpecAnnotator : Annotator {

    override fun annotate(element: PsiElement, holder: AnnotationHolder) {
        if (element !is PsiFile) return

        val settings = SecuritySettings.getInstance()
        val missingSecurityOn = settings.isEnabled(SecurityRule.OPENAPI_MISSING_SECURITY)
        val corsOn = settings.isEnabled(SecurityRule.OPENAPI_PERMISSIVE_CORS)
        if (!missingSecurityOn && !corsOn) return

        val text = element.text
        if (!SPEC_MARKER.containsMatchIn(text)) return

        if (missingSecurityOn) {
            OpenApiSpecDetector.hasEmptyTopLevelSecurity(text)?.let { finding ->
                reportOnLine(element, text, finding.line, finding.description, holder)
            }
        }
        if (corsOn) {
            OpenApiSpecDetector.findWildcardCorsWithCredentials(text)?.let { finding ->
                reportOnLine(element, text, finding.line, finding.description, holder)
            }
        }
    }

    private fun reportOnLine(file: PsiFile, text: String, lineNumber: Int, message: String, holder: AnnotationHolder) {
        val lines = text.lines()
        var offset = 0
        for (i in 0 until (lineNumber - 1).coerceAtMost(lines.size)) {
            offset += lines[i].length + 1
        }
        val lineLength = lines.getOrNull(lineNumber - 1)?.length ?: 0
        val range = com.intellij.openapi.util.TextRange(offset, (offset + lineLength).coerceAtMost(text.length))
        holder.newAnnotation(HighlightSeverity.WARNING, message).range(range).create()
    }
}
