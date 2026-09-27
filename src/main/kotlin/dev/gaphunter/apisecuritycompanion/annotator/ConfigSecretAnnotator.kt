package dev.gaphunter.apisecuritycompanion.annotator

import com.intellij.json.psi.JsonProperty
import com.intellij.json.psi.JsonStringLiteral
import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.Annotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.lang.properties.parsing.PropertiesTokenTypes
import com.intellij.lang.properties.psi.Property
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiPlainTextFile
import dev.gaphunter.apisecuritycompanion.detect.ConfigContext
import dev.gaphunter.apisecuritycompanion.detect.ConfigSecretScanner
import dev.gaphunter.apisecuritycompanion.detect.SecretFinding
import dev.gaphunter.apisecuritycompanion.licensing.CheckLicense
import dev.gaphunter.apisecuritycompanion.review.ReviewPrompt
import dev.gaphunter.apisecuritycompanion.settings.SecurityRule
import dev.gaphunter.apisecuritycompanion.settings.SecuritySettings
import dev.gaphunter.apisecuritycompanion.settings.TeamPolicyLoader
import org.jetbrains.annotations.TestOnly
import org.jetbrains.yaml.psi.YAMLKeyValue
import org.jetbrains.yaml.psi.YAMLScalar

/**
 * Secrets in configuration files: JSON, YAML, `.properties` and `.env`
 * (the Java/Kotlin literals are [SecretAndTransportAnnotator]'s job). It also
 * covers the MCP server configs AI tools read (`mcp.json`,
 * `claude_desktop_config.json`, ...), where API keys are pasted into `env` and
 * `headers` all the time.
 *
 * Exact-format tokens are Free (rule [SecurityRule.CONFIG_FILE_SECRETS]); the
 * name + entropy heuristic is the Pro rule [SecurityRule.CONFIG_SECRET_HEURISTIC],
 * active with a license or when the project's team policy forces it, the same
 * gate as the other Pro rules (see [ProSecurityAnnotator]).
 *
 * Template files (`.env.example`, `*.sample`), lock files and build output
 * directories are skipped, and so is anything under a key called `example`/
 * `description` -- OpenAPI specs are full of sample tokens that aren't leaks.
 */
class ConfigSecretAnnotator : Annotator {

    override fun annotate(element: PsiElement, holder: AnnotationHolder) {
        val file = element.containingFile ?: return
        val virtualFile = file.virtualFile ?: file.originalFile.virtualFile ?: return
        if (virtualFile.length > MAX_FILE_BYTES) return
        val settings = SecuritySettings.getInstance()
        if (!settings.isEnabled(SecurityRule.SECRET_DETECTION) || !settings.isEnabled(SecurityRule.CONFIG_FILE_SECRETS)) return
        if (ConfigSecretScanner.isTemplateOrGeneratedFile(virtualFile.name) || ConfigSecretScanner.isInSkippedDirectory(virtualFile.path)) return

        val heuristic = isHeuristicActive(file.project)
        when (element) {
            is JsonStringLiteral -> annotateJson(element, virtualFile.path, heuristic, holder)
            is YAMLScalar -> annotateYaml(element, virtualFile.path, heuristic, holder)
            is Property -> annotateProperty(element, virtualFile.path, heuristic, holder)
            is PsiPlainTextFile -> if (isDotEnvName(virtualFile.name)) annotateDotEnv(element, virtualFile.path, heuristic, holder)
        }
    }

    // ---------- JSON ----------

    private fun annotateJson(literal: JsonStringLiteral, path: String, heuristic: Boolean, holder: AnnotationHolder) {
        val parent = literal.parent
        if (parent is JsonProperty && parent.nameElement == literal) return // a key, not a value
        val keys = generateSequence<PsiElement>(literal) { it.parent }
            .filterIsInstance<JsonProperty>()
            .map { it.name }
            .toList()
        val context = ConfigContext(keys.firstOrNull(), keys.drop(1))
        report(literal, literal.textRange, ConfigSecretScanner.scanValue(literal.value, context, heuristic), path, holder)
    }

    // ---------- YAML ----------

    private fun annotateYaml(scalar: YAMLScalar, path: String, heuristic: Boolean, holder: AnnotationHolder) {
        val keys = generateSequence<PsiElement>(scalar) { it.parent }
            .filterIsInstance<YAMLKeyValue>()
            .map { it.keyText }
            .toList()
        val context = ConfigContext(keys.firstOrNull(), keys.drop(1))
        report(scalar, scalar.textRange, ConfigSecretScanner.scanValue(scalar.textValue, context, heuristic), path, holder)
    }

    // ---------- .properties ----------

    private fun annotateProperty(property: Property, path: String, heuristic: Boolean, holder: AnnotationHolder) {
        val value = property.value ?: return
        val valueNode = property.node.findChildByType(PropertiesTokenTypes.VALUE_CHARACTERS) ?: return
        val context = ConfigContext(property.key)
        report(property, valueNode.textRange, ConfigSecretScanner.scanValue(value, context, heuristic), path, holder)
    }

    // ---------- .env ----------

    private fun annotateDotEnv(file: PsiFile, path: String, heuristic: Boolean, holder: AnnotationHolder) {
        val base = file.textRange.startOffset
        for (hit in ConfigSecretScanner.scanDotEnv(file.text, heuristic)) {
            report(file, TextRange(base + hit.start, base + hit.end), hit.finding, path, holder)
        }
    }

    private fun isDotEnvName(name: String): Boolean {
        val lower = name.lowercase()
        return lower == ".env" || lower.startsWith(".env.") || lower.endsWith(".env")
    }

    // ---------- shared ----------

    private fun report(element: PsiElement, range: TextRange, finding: SecretFinding?, path: String, holder: AnnotationHolder) {
        if (finding == null) return
        val advice = if (ConfigSecretScanner.isMcpConfig(path)) {
            "MCP server configs are a common source of leaked keys -- reference an environment variable instead"
        } else {
            "use an environment variable or a secret store instead"
        }
        holder.newAnnotation(HighlightSeverity.WARNING, "Potential secret: ${finding.description} -- $advice")
            .range(range)
            .create()
        recordHit(element, range, "config-secret")
    }

    private fun recordHit(element: PsiElement, range: TextRange, kind: String) {
        val file = element.containingFile
        val path = file.virtualFile?.path ?: return
        val line = file.viewProvider.document?.getLineNumber(range.startOffset) ?: -1
        ReviewPrompt.recordHit(file.project, "$path:$line:$kind")
    }

    private fun isHeuristicActive(project: Project): Boolean {
        forceHeuristicForTests?.let { return it }
        val rule = SecurityRule.CONFIG_SECRET_HEURISTIC
        if (!SecuritySettings.getInstance().isEnabled(rule)) return false
        return CheckLicense.isLicensed() == true || rule.id in TeamPolicyLoader.forcedRuleIds(project)
    }

    companion object {
        private const val MAX_FILE_BYTES = 512_000L

        /**
         * Lets a test exercise the Pro path without a real license (the test IDE has none and a
         * light fixture has no project directory to hold a team-policy file). Never set in production.
         */
        @set:TestOnly
        @Volatile
        var forceHeuristicForTests: Boolean? = null
    }
}
