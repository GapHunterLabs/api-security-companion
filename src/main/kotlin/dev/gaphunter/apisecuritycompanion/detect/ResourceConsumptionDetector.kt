package dev.gaphunter.apisecuritycompanion.detect

/**
 * OWASP API Security Top 10 -- Unrestricted Resource Consumption (API4):
 * a parameter that controls how much data/work a single request
 * triggers (page size, limit, count) with no visible upper-bound
 * validation annotation lets a client request an unbounded amount of
 * work from one call. Matches on a fixed, conservative set of parameter
 * names specifically to keep false positives low -- a plain "size"/
 * "count" parameter unrelated to pagination on an endpoint we can't
 * distinguish is an accepted, documented tradeoff of a name-based
 * heuristic.
 */
object ResourceConsumptionDetector {
    private val LIMIT_PARAM_NAMES = setOf(
        "limit", "pagesize", "page_size", "size", "count", "maxresults", "max_results", "top", "take",
    )
    private val BOUND_VALIDATION_ANNOTATIONS = setOf("Max", "DecimalMax", "Positive", "PositiveOrZero", "Range")

    fun isUnboundedLimitParameter(paramName: String, paramAnnotations: Set<String>): Boolean {
        if (paramName.lowercase() !in LIMIT_PARAM_NAMES) return false
        return BOUND_VALIDATION_ANNOTATIONS.none { it in paramAnnotations }
    }
}
