package dev.gaphunter.apisecuritycompanion.detect

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BolaDetectorTest {
    @Test
    fun `recognizes id-shaped parameter names`() {
        assertTrue(BolaDetector.hasIdLikeParameterName("id"))
        assertTrue(BolaDetector.hasIdLikeParameterName("orderId"))
        assertTrue(BolaDetector.hasIdLikeParameterName("user_id"))
        assertFalse(BolaDetector.hasIdLikeParameterName("name"))
        assertFalse(BolaDetector.hasIdLikeParameterName("bidder")) // contains "id" but isn't id-shaped
    }

    @Test
    fun `flags a rest endpoint with an id parameter and no auth hint`() {
        val body = "public Order getOrder(String orderId) { return repository.findById(orderId); }"
        assertTrue(BolaDetector.isPotentialRisk(isRestEndpoint = true, hasIdLikeParameter = true, methodBodyText = body))
    }

    @Test
    fun `does not flag when an auth check hint is present`() {
        val body = "public Order getOrder(String orderId) { " +
            "if (!order.getOwnerId().equals(getCurrentUser().getId())) throw new Forbidden(); " +
            "return repository.findById(orderId); }"
        assertFalse(BolaDetector.isPotentialRisk(isRestEndpoint = true, hasIdLikeParameter = true, methodBodyText = body))
    }

    @Test
    fun `does not flag a non-rest method`() {
        assertFalse(BolaDetector.isPotentialRisk(isRestEndpoint = false, hasIdLikeParameter = true, methodBodyText = "return repo.findById(id);"))
    }

    @Test
    fun `does not flag a rest endpoint with no id-like parameter`() {
        assertFalse(BolaDetector.isPotentialRisk(isRestEndpoint = true, hasIdLikeParameter = false, methodBodyText = "return repo.findAll();"))
    }
}
