package dev.gaphunter.apisecuritycompanion.detect

import com.intellij.testFramework.fixtures.BasePlatformTestCase
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * Real PSI resolution, not mocked -- confirms [KotlinTypeAnnotationResolver]
 * actually resolves a Kotlin type reference to its declaring class's
 * annotations, both Kotlin-to-Kotlin and Kotlin-to-Java (a Kotlin REST
 * controller returning a Java JPA entity is a completely realistic
 * mixed-language case in a real Spring Boot codebase).
 */
class KotlinTypeAnnotationResolverTest : BasePlatformTestCase() {

    private fun namedFunction(file: KtFile, name: String): KtNamedFunction {
        var found: KtNamedFunction? = null
        file.accept(object : org.jetbrains.kotlin.psi.KtTreeVisitorVoid() {
            override fun visitNamedFunction(function: KtNamedFunction) {
                super.visitNamedFunction(function)
                if (function.name == name) found = function
            }
        })
        return found ?: error("function $name not found")
    }

    fun testResolvesReturnTypeAnnotationsToAKotlinClassInTheSameFile() {
        val file = myFixture.configureByText(
            "OrderController.kt",
            """
            annotation class Entity
            annotation class GetMapping

            @Entity
            class Order(val id: String)

            class OrderController {
                @GetMapping
                fun getOrder(): Order = TODO()
            }
            """.trimIndent(),
        ) as KtFile

        val function = namedFunction(file, "getOrder")
        val annotations = KotlinTypeAnnotationResolver.resolve(function.typeReference!!)
        assertTrue("expected Entity in $annotations", "Entity" in annotations)
    }

    fun testResolvesParameterTypeAnnotationsToAKotlinClass() {
        val file = myFixture.configureByText(
            "OrderController.kt",
            """
            annotation class Entity
            annotation class PostMapping

            @Entity
            class Order(val id: String)

            class OrderController {
                @PostMapping
                fun createOrder(order: Order) {}
            }
            """.trimIndent(),
        ) as KtFile

        val function = namedFunction(file, "createOrder")
        val paramType = function.valueParameters.first().typeReference!!
        val annotations = KotlinTypeAnnotationResolver.resolve(paramType)
        assertTrue("expected Entity in $annotations", "Entity" in annotations)
    }

    fun testResolvesAcrossLanguagesToAJavaClass() {
        myFixture.addFileToProject(
            "Order.java",
            """
            @interface Entity {}

            @Entity
            public class Order {
                private String id;
            }
            """.trimIndent(),
        )
        val file = myFixture.configureByText(
            "OrderController.kt",
            """
            annotation class GetMapping

            class OrderController {
                @GetMapping
                fun getOrder(): Order = TODO()
            }
            """.trimIndent(),
        ) as KtFile

        val function = namedFunction(file, "getOrder")
        val annotations = KotlinTypeAnnotationResolver.resolve(function.typeReference!!)
        assertTrue("expected Entity in $annotations (cross-language Kotlin->Java resolution)", "Entity" in annotations)
    }

    fun testUnresolvableTypeReturnsEmptySetInsteadOfThrowing() {
        val file = myFixture.configureByText(
            "OrderController.kt",
            """
            class OrderController {
                fun getOrder(): DoesNotExist = TODO()
            }
            """.trimIndent(),
        ) as KtFile

        val function = namedFunction(file, "getOrder")
        val annotations = KotlinTypeAnnotationResolver.resolve(function.typeReference!!)
        assertTrue(annotations.isEmpty())
    }

    fun testPlainTypeWithNoAnnotationsReturnsEmptySet() {
        val file = myFixture.configureByText(
            "OrderController.kt",
            """
            class PlainData(val id: String)

            class OrderController {
                fun getData(): PlainData = TODO()
            }
            """.trimIndent(),
        ) as KtFile

        val function = namedFunction(file, "getData")
        val annotations = KotlinTypeAnnotationResolver.resolve(function.typeReference!!)
        assertTrue(annotations.isEmpty())
    }
}
