package dev.gaphunter.apisecuritycompanion.detect

/**
 * OWASP API Security Top 10 -- Broken Object Level Authorization (API1):
 * a heuristic, not a data-flow analysis. Flags a REST endpoint that takes
 * an object-identifier-shaped parameter (`id`, `*Id`, `*_id`) with no
 * visible authorization/ownership check anywhere in the method body.
 * Always a "worth a manual look" signal, never a certainty -- expect
 * false positives on endpoints whose authorization runs through a
 * mechanism this text-based heuristic doesn't recognize (e.g. a security
 * filter/interceptor upstream of the method). Framed as WARNING severity
 * with "Potential" in the message for exactly that reason.
 */
object BolaDetector {
    private val ID_PARAM_NAME = Regex("(?i)^(id|.+Id|.+_id)$")

    private val AUTH_CHECK_HINTS = listOf(
        "getPrincipal", "SecurityContext", "Authentication", "currentUser", "getCurrentUser",
        "PreAuthorize", "Secured", "RolesAllowed", "hasPermission", "isOwner", "checkOwnership",
        "assertOwner", "ownerId", "userId",
    )

    fun hasIdLikeParameterName(paramName: String): Boolean = ID_PARAM_NAME.matches(paramName)

    fun isPotentialRisk(isRestEndpoint: Boolean, hasIdLikeParameter: Boolean, methodBodyText: String): Boolean {
        if (!isRestEndpoint || !hasIdLikeParameter) return false
        return AUTH_CHECK_HINTS.none { methodBodyText.contains(it) }
    }
}
