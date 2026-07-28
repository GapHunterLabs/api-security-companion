package dev.gaphunter.apisecuritycompanion.detect

/**
 * OWASP API Security Top 10 — "Excessive Data Exposure": a REST endpoint
 * that returns a persistence entity directly instead of a DTO leaks
 * whatever fields the entity happens to carry (password hashes, internal
 * flags) to every client of the API, forever, without anyone deciding to
 * expose them on purpose. Pure heuristic over annotation names so it has
 * no dependency on which web/persistence framework's actual annotation
 * classes are on the classpath.
 */
object ExcessiveExposureDetector {

    private val REST_MAPPING_ANNOTATIONS = setOf(
        "GetMapping", "PostMapping", "PutMapping", "PatchMapping", "DeleteMapping", "RequestMapping",
        "GET", "POST", "PUT", "PATCH", "DELETE", // JAX-RS
    )

    private val PERSISTENCE_ENTITY_ANNOTATIONS = setOf("Entity", "Document", "Table")

    fun isExposingEntityDirectly(methodAnnotations: Set<String>, returnTypeAnnotations: Set<String>): Boolean {
        val isRestEndpoint = methodAnnotations.any { it in REST_MAPPING_ANNOTATIONS }
        val returnsRawEntity = returnTypeAnnotations.any { it in PERSISTENCE_ENTITY_ANNOTATIONS }
        return isRestEndpoint && returnsRawEntity
    }

    /**
     * Mass Assignment counterpart of the same complaint class: a REST
     * write endpoint (POST/PUT/PATCH) whose parameter is itself annotated
     * as a persistence entity means the client's raw JSON body is bound
     * straight onto persisted columns, including ones the client was
     * never meant to set (e.g. `isAdmin`).
     */
    fun isMassAssignmentRisk(methodAnnotations: Set<String>, parameterTypeAnnotations: Set<String>): Boolean {
        val isWriteEndpoint = methodAnnotations.any {
            it in setOf("PostMapping", "PutMapping", "PatchMapping", "POST", "PUT", "PATCH")
        }
        val bindsRawEntity = parameterTypeAnnotations.any { it in PERSISTENCE_ENTITY_ANNOTATIONS }
        return isWriteEndpoint && bindsRawEntity
    }
}
