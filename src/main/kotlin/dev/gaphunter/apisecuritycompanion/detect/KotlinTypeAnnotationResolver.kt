package dev.gaphunter.apisecuritycompanion.detect

import com.intellij.psi.PsiClass
import com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtTypeReference

/**
 * Resolves a Kotlin type reference's simple-name part to the
 * annotation-name set of its underlying class declaration -- Kotlin or
 * Java, since a Kotlin type reference can resolve to either (a Kotlin
 * function can return/accept a Java JPA `@Entity`). Uses the reference's
 * own standard `PsiElement.reference` (the same mechanism Ctrl+Click/Go
 * to Declaration uses for any language), not the heavier analysis/
 * BindingContext API, deliberately -- keeps this K1/K2 neutral and
 * avoids a second, more failure-prone resolution path.
 *
 * Kept separate from [dev.gaphunter.apisecuritycompanion.annotator.ProSecurityAnnotator]
 * so it's directly unit-testable with a real `BasePlatformTestCase`
 * fixture, without needing to fake a license.
 */
object KotlinTypeAnnotationResolver {
    fun resolve(typeReference: KtTypeReference): Set<String> {
        val nameRef = PsiTreeUtil.findChildOfType(typeReference, KtNameReferenceExpression::class.java) ?: return emptySet()
        return when (val resolved = nameRef.reference?.resolve()) {
            is KtClass -> resolved.annotationEntries.mapNotNull { it.shortName?.asString() }.toSet()
            is PsiClass -> resolved.annotations.mapNotNull { it.nameReferenceElement?.referenceName }.toSet()
            else -> emptySet()
        }
    }
}
