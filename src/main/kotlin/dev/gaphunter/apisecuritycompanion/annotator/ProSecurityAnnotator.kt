package dev.gaphunter.apisecuritycompanion.annotator

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.Annotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiMethod
import dev.gaphunter.apisecuritycompanion.detect.BolaDetector
import dev.gaphunter.apisecuritycompanion.detect.ExcessiveExposureDetector
import dev.gaphunter.apisecuritycompanion.detect.KotlinTypeAnnotationResolver
import dev.gaphunter.apisecuritycompanion.detect.ResourceConsumptionDetector
import dev.gaphunter.apisecuritycompanion.detect.RestEndpointAnnotations
import dev.gaphunter.apisecuritycompanion.licensing.CheckLicense
import dev.gaphunter.apisecuritycompanion.settings.SecurityRule
import dev.gaphunter.apisecuritycompanion.settings.SecuritySettings
import dev.gaphunter.apisecuritycompanion.settings.TeamPolicyLoader
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * Pro-tier checks: Kotlin support for Excessive Data Exposure/Mass
 * Assignment (the checks in [EntityExposureAnnotator] are Java-only),
 * Broken Object Level Authorization (OWASP API1), and Unrestricted
 * Resource Consumption (OWASP API4) -- for both Java and Kotlin.
 *
 * Registered unconditionally, same as every other annotator in this
 * plugin (SDK_GOTCHAS.md SS8: the plugin loads identically for everyone,
 * only the specific paid feature gates on license) -- a rule only
 * produces annotations when [isRuleActive] is true, i.e. the user has a
 * valid license OR the project's `.gaphunter-security-rules` team
 * policy file forces that specific rule regardless of individual
 * licensing (see [TeamPolicyLoader]). Kotlin type resolution itself
 * lives in [KotlinTypeAnnotationResolver], kept separate so it's
 * directly unit-testable without needing to fake a license.
 */
class ProSecurityAnnotator : Annotator {

    override fun annotate(element: PsiElement, holder: AnnotationHolder) {
        when (element) {
            is PsiMethod -> annotateJavaMethod(element, holder)
            is KtNamedFunction -> annotateKotlinFunction(element, holder)
        }
    }

    private fun isRuleActive(project: Project, rule: SecurityRule): Boolean {
        if (!SecuritySettings.getInstance().isEnabled(rule)) return false
        val licensed = CheckLicense.isLicensed() == true
        val teamForced = rule.id in TeamPolicyLoader.forcedRuleIds(project)
        return licensed || teamForced
    }

    // ---------- Java ----------

    private fun annotateJavaMethod(method: PsiMethod, holder: AnnotationHolder) {
        val project = method.project
        val methodAnnotations = method.annotations.mapNotNull { it.nameReferenceElement?.referenceName }.toSet()
        val isRestEndpoint = RestEndpointAnnotations.isRestEndpoint(methodAnnotations)

        if (isRuleActive(project, SecurityRule.BROKEN_OBJECT_LEVEL_AUTH)) {
            val hasIdParam = method.parameterList.parameters.any { BolaDetector.hasIdLikeParameterName(it.name) }
            if (BolaDetector.isPotentialRisk(isRestEndpoint, hasIdParam, method.text)) {
                holder.newAnnotation(
                    HighlightSeverity.WARNING,
                    "Potential Broken Object Level Authorization (OWASP API1): this endpoint takes an " +
                        "object ID but no authorization/ownership check is visible in its body -- worth a manual review",
                ).range(method.nameIdentifier?.textRange ?: method.textRange).create()
            }
        }

        if (isRestEndpoint && isRuleActive(project, SecurityRule.UNRESTRICTED_RESOURCE_CONSUMPTION)) {
            for (parameter in method.parameterList.parameters) {
                val paramAnnotations = parameter.annotations.mapNotNull { it.nameReferenceElement?.referenceName }.toSet()
                if (ResourceConsumptionDetector.isUnboundedLimitParameter(parameter.name, paramAnnotations)) {
                    holder.newAnnotation(
                        HighlightSeverity.WARNING,
                        "Potential Unrestricted Resource Consumption (OWASP API4): '${parameter.name}' looks like a " +
                            "page-size/limit parameter with no upper-bound validation -- a client can request an unbounded amount of data",
                    ).range(parameter.textRange).create()
                }
            }
        }

        // Excessive Data Exposure / Mass Assignment for Java is
        // EntityExposureAnnotator's job (Free tier, already shipped) --
        // this annotator only adds the Kotlin path, in annotateKotlinFunction.
    }

    // ---------- Kotlin ----------

    private fun annotateKotlinFunction(function: KtNamedFunction, holder: AnnotationHolder) {
        val project = function.project
        val methodAnnotations = function.annotationEntries.mapNotNull { it.shortName?.asString() }.toSet()
        val isRestEndpoint = RestEndpointAnnotations.isRestEndpoint(methodAnnotations)

        if (isRuleActive(project, SecurityRule.EXCESSIVE_DATA_EXPOSURE)) {
            val returnAnnotations = function.typeReference?.let { KotlinTypeAnnotationResolver.resolve(it) } ?: emptySet()
            if (ExcessiveExposureDetector.isExposingEntityDirectly(methodAnnotations, returnAnnotations)) {
                holder.newAnnotation(
                    HighlightSeverity.WARNING,
                    "This endpoint returns a persistence entity directly -- every field on it, including " +
                        "ones never meant to be public, gets serialized to every caller",
                ).range(function.nameIdentifier?.textRange ?: function.textRange).create()
            }
        }

        if (isRuleActive(project, SecurityRule.MASS_ASSIGNMENT)) {
            for (parameter in function.valueParameters) {
                val paramAnnotations = parameter.typeReference?.let { KotlinTypeAnnotationResolver.resolve(it) } ?: emptySet()
                if (ExcessiveExposureDetector.isMassAssignmentRisk(methodAnnotations, paramAnnotations)) {
                    holder.newAnnotation(
                        HighlightSeverity.WARNING,
                        "This write endpoint binds the request body directly onto a persistence entity -- a " +
                            "client can set any column, including ones like 'isAdmin' that were never meant to be client-writable",
                    ).range(parameter.textRange).create()
                }
            }
        }

        if (isRuleActive(project, SecurityRule.BROKEN_OBJECT_LEVEL_AUTH)) {
            val hasIdParam = function.valueParameters.any { param -> param.name?.let { BolaDetector.hasIdLikeParameterName(it) } == true }
            if (BolaDetector.isPotentialRisk(isRestEndpoint, hasIdParam, function.text)) {
                holder.newAnnotation(
                    HighlightSeverity.WARNING,
                    "Potential Broken Object Level Authorization (OWASP API1): this endpoint takes an " +
                        "object ID but no authorization/ownership check is visible in its body -- worth a manual review",
                ).range(function.nameIdentifier?.textRange ?: function.textRange).create()
            }
        }

        if (isRestEndpoint && isRuleActive(project, SecurityRule.UNRESTRICTED_RESOURCE_CONSUMPTION)) {
            for (parameter in function.valueParameters) {
                val name = parameter.name ?: continue
                val paramAnnotations = parameter.annotationEntries.mapNotNull { it.shortName?.asString() }.toSet()
                if (ResourceConsumptionDetector.isUnboundedLimitParameter(name, paramAnnotations)) {
                    holder.newAnnotation(
                        HighlightSeverity.WARNING,
                        "Potential Unrestricted Resource Consumption (OWASP API4): '$name' looks like a " +
                            "page-size/limit parameter with no upper-bound validation -- a client can request an unbounded amount of data",
                    ).range(parameter.textRange).create()
                }
            }
        }
    }
}
