package dev.gaphunter.apisecuritycompanion.detect

data class TransportFinding(val kind: String, val description: String)

/**
 * Pure text-based detection of two well-known transport-security
 * anti-patterns: plaintext HTTP URLs pointed at real hosts, and the
 * classic "trust every certificate" `X509TrustManager` implementation.
 * Operates on plain strings (a literal value, or a class body's source
 * text) so it never needs a live PSI tree to be tested.
 */
object InsecureTransportDetector {

    private val HTTP_URL = Regex("""^http://([^/]+)""", RegexOption.IGNORE_CASE)

    private val LOCAL_HOSTS = setOf("localhost", "127.0.0.1", "0.0.0.0")
    private val PRIVATE_IP_PREFIXES = listOf("10.", "192.168.", "169.254.")
    private val PRIVATE_172_RANGE = Regex("""^172\.(1[6-9]|2\d|3[01])\.""")

    fun scanUrlLiteral(value: String): TransportFinding? {
        val host = HTTP_URL.find(value)?.groupValues?.get(1)?.substringBefore(':') ?: return null
        if (host in LOCAL_HOSTS) return null
        if (PRIVATE_IP_PREFIXES.any { host.startsWith(it) }) return null
        if (PRIVATE_172_RANGE.containsMatchIn(host)) return null
        return TransportFinding("PLAINTEXT_HTTP", "Plaintext http:// URL to a non-local host ($host)")
    }

    fun scanTrustManagerBody(classSourceText: String): TransportFinding? {
        if (!classSourceText.contains("X509TrustManager")) return null
        if (!classSourceText.contains("checkServerTrusted")) return null

        val serverTrustedBody = extractMethodBody(classSourceText, "checkServerTrusted") ?: return null
        val clientTrustedBody = extractMethodBody(classSourceText, "checkClientTrusted")

        val serverTrustedIsNoOp = !serverTrustedBody.contains("throw")
        val clientTrustedIsNoOp = clientTrustedBody == null || !clientTrustedBody.contains("throw")

        if (serverTrustedIsNoOp && clientTrustedIsNoOp) {
            return TransportFinding(
                "TRUST_ALL_CERTIFICATES",
                "X509TrustManager never throws in checkServerTrusted/checkClientTrusted — accepts every certificate",
            )
        }
        return null
    }

    private fun extractMethodBody(sourceText: String, methodName: String): String? {
        val nameIndex = sourceText.indexOf(methodName)
        if (nameIndex < 0) return null
        val openBrace = sourceText.indexOf('{', nameIndex)
        if (openBrace < 0) return null

        var depth = 0
        var i = openBrace
        while (i < sourceText.length) {
            when (sourceText[i]) {
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return sourceText.substring(openBrace + 1, i)
                }
            }
            i++
        }
        return null
    }
}
