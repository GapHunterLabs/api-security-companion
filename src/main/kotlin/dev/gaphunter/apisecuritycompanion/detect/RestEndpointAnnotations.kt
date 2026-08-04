package dev.gaphunter.apisecuritycompanion.detect

/** Shared REST-mapping-annotation set for the Pro-tier detectors
 * (BOLA, Resource Consumption) -- kept separate from
 * [ExcessiveExposureDetector]'s own copy rather than refactoring
 * already-shipped Free-tier code to share it. */
object RestEndpointAnnotations {
    val MAPPING = setOf(
        "GetMapping", "PostMapping", "PutMapping", "PatchMapping", "DeleteMapping", "RequestMapping",
        "GET", "POST", "PUT", "PATCH", "DELETE", // JAX-RS
    )

    fun isRestEndpoint(methodAnnotations: Set<String>): Boolean = methodAnnotations.any { it in MAPPING }
}
