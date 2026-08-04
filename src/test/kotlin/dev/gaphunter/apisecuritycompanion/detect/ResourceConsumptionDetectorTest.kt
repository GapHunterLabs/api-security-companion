package dev.gaphunter.apisecuritycompanion.detect

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResourceConsumptionDetectorTest {
    @Test
    fun `flags a limit-shaped parameter with no bound validation`() {
        assertTrue(ResourceConsumptionDetector.isUnboundedLimitParameter("limit", emptySet()))
        assertTrue(ResourceConsumptionDetector.isUnboundedLimitParameter("pageSize", emptySet()))
        assertTrue(ResourceConsumptionDetector.isUnboundedLimitParameter("maxResults", emptySet()))
    }

    @Test
    fun `does not flag when a bound validation annotation is present`() {
        assertFalse(ResourceConsumptionDetector.isUnboundedLimitParameter("limit", setOf("Max")))
        assertFalse(ResourceConsumptionDetector.isUnboundedLimitParameter("size", setOf("Range")))
    }

    @Test
    fun `does not flag an unrelated parameter name`() {
        assertFalse(ResourceConsumptionDetector.isUnboundedLimitParameter("orderId", emptySet()))
        assertFalse(ResourceConsumptionDetector.isUnboundedLimitParameter("name", emptySet()))
    }
}
