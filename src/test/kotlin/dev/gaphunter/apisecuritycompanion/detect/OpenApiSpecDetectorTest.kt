package dev.gaphunter.apisecuritycompanion.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OpenApiSpecDetectorTest {

    @Test
    fun flagsEmptyTopLevelSecurityList() {
        val spec = """
            openapi: 3.0.0
            info:
              title: Orders API
            security: []
            paths:
              /orders:
                get:
                  summary: List orders
        """.trimIndent()
        val finding = OpenApiSpecDetector.hasEmptyTopLevelSecurity(spec)
        assertEquals("EMPTY_SECURITY_SCHEME", finding?.kind)
    }

    @Test
    fun flagsSecurityKeyWithNoSchemesAtAll() {
        val spec = """
            openapi: 3.0.0
            security:
            paths:
              /orders:
                get:
                  summary: List orders
        """.trimIndent()
        assertEquals("EMPTY_SECURITY_SCHEME", OpenApiSpecDetector.hasEmptyTopLevelSecurity(spec)?.kind)
    }

    @Test
    fun doesNotFlagSecurityWithARealScheme() {
        val spec = """
            openapi: 3.0.0
            security:
              - bearerAuth: []
            paths:
              /orders:
                get:
                  summary: List orders
        """.trimIndent()
        assertNull(OpenApiSpecDetector.hasEmptyTopLevelSecurity(spec))
    }

    @Test
    fun doesNotFlagSpecWithNoSecurityKeyAtAll() {
        val spec = """
            openapi: 3.0.0
            paths:
              /orders:
                get:
                  summary: List orders
        """.trimIndent()
        assertNull(OpenApiSpecDetector.hasEmptyTopLevelSecurity(spec))
    }

    @Test
    fun flagsWildcardCorsWithCredentials() {
        // The detector is deliberately a simple direct key:value regex scan, not a YAML-aware
        // traversal (see class doc) — this is the shape of spec text it's meant to catch, as
        // opposed to a value buried under a nested schema/example structure several lines below
        // the header name.
        val spec = """
            openapi: 3.0.0
            paths:
              /orders:
                get:
                  responses:
                    '200':
                      headers:
                        Access-Control-Allow-Origin: "*"
                        Access-Control-Allow-Credentials: "true"
        """.trimIndent()
        val finding = OpenApiSpecDetector.findWildcardCorsWithCredentials(spec)
        assertEquals("PERMISSIVE_CORS_WITH_CREDENTIALS", finding?.kind)
    }

    @Test
    fun doesNotFlagWildcardCorsWithoutCredentials() {
        val spec = """
            Access-Control-Allow-Origin: "*"
        """.trimIndent()
        assertNull(OpenApiSpecDetector.findWildcardCorsWithCredentials(spec))
    }

    @Test
    fun doesNotFlagSpecificOriginEvenWithCredentials() {
        val spec = """
            Access-Control-Allow-Origin: "https://acme-corp.com"
            Access-Control-Allow-Credentials: "true"
        """.trimIndent()
        assertNull(OpenApiSpecDetector.findWildcardCorsWithCredentials(spec))
    }
}
