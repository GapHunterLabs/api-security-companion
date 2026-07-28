package dev.gaphunter.apisecuritycompanion.detect

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ExcessiveExposureDetectorTest {

    @Test
    fun flagsGetMappingReturningAnEntity() {
        assertTrue(
            ExcessiveExposureDetector.isExposingEntityDirectly(
                methodAnnotations = setOf("GetMapping"),
                returnTypeAnnotations = setOf("Entity"),
            ),
        )
    }

    @Test
    fun flagsJaxRsGetReturningADocument() {
        assertTrue(
            ExcessiveExposureDetector.isExposingEntityDirectly(
                methodAnnotations = setOf("GET", "Produces"),
                returnTypeAnnotations = setOf("Document"),
            ),
        )
    }

    @Test
    fun doesNotFlagNonRestMethodReturningAnEntity() {
        assertFalse(
            ExcessiveExposureDetector.isExposingEntityDirectly(
                methodAnnotations = setOf("Transactional"),
                returnTypeAnnotations = setOf("Entity"),
            ),
        )
    }

    @Test
    fun doesNotFlagRestMethodReturningAPlainDto() {
        assertFalse(
            ExcessiveExposureDetector.isExposingEntityDirectly(
                methodAnnotations = setOf("GetMapping"),
                returnTypeAnnotations = emptySet(),
            ),
        )
    }

    @Test
    fun flagsPostMappingBindingAnEntityParameter() {
        assertTrue(
            ExcessiveExposureDetector.isMassAssignmentRisk(
                methodAnnotations = setOf("PostMapping"),
                parameterTypeAnnotations = setOf("Entity"),
            ),
        )
    }

    @Test
    fun doesNotFlagGetMappingWithEntityParameter() {
        // A GET request with an @Entity-annotated query parameter type is unusual but not a
        // write/mass-assignment risk — nothing is being persisted from client input here.
        assertFalse(
            ExcessiveExposureDetector.isMassAssignmentRisk(
                methodAnnotations = setOf("GetMapping"),
                parameterTypeAnnotations = setOf("Entity"),
            ),
        )
    }

    @Test
    fun doesNotFlagPostMappingWithDtoParameter() {
        assertFalse(
            ExcessiveExposureDetector.isMassAssignmentRisk(
                methodAnnotations = setOf("PostMapping"),
                parameterTypeAnnotations = emptySet(),
            ),
        )
    }
}
