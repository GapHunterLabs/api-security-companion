package dev.gaphunter.apisecuritycompanion.detect.ml

/**
 * Kotlin-side implementation of `ml-training/FEATURE_SPEC.md` -- the
 * training script (`ml-training/train_model.py`) is the other half of
 * this pair, and both MUST produce byte-identical output for the same
 * input string. [SecretFeatureExtractorTest] checks that identity
 * mechanically against `cross_check_vectors.json` (generated once by the
 * Python side) on every build, rather than relying on this comment.
 *
 * Deliberately hand-engineered features + a small hashed-trigram bucket
 * instead of a raw character-embedding model: every formula here is
 * plain arithmetic, nothing that depends on a specific library version
 * staying in sync across two languages. The one hash function used
 * (bucket index for a character trigram) is the standard JVM
 * `String.hashCode()` algorithm -- already implemented identically by
 * Kotlin's `String.hashCode()` on the JVM, which is why only the
 * Python side needed a from-scratch reimplementation of that formula.
 */
object SecretFeatureExtractor {

    const val FEATURE_DIM = 76
    private const val TRIGRAM_BUCKETS = 64

    private val HEX_CHARS = ('0'..'9') + ('a'..'f') + ('A'..'F')
    private val BASE64_CHARS = ('A'..'Z') + ('a'..'z') + ('0'..'9') + listOf('+', '/')
    private val UUID_PATTERN = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

    fun extract(s: String): FloatArray {
        val features = FloatArray(FEATURE_DIM)
        val length = s.length
        if (length == 0) return features

        features[0] = (minOf(length, 128) / 128.0).toFloat()
        features[1] = (shannonEntropyBitsPerChar(s) / 8.0).toFloat()

        var digit = 0
        var upper = 0
        var lower = 0
        for (c in s) {
            when {
                c.isDigit() -> digit++
                c.isUpperCase() -> upper++
                c.isLowerCase() -> lower++
            }
        }
        val symbol = length - digit - upper - lower

        features[2] = digit.toFloat() / length
        features[3] = upper.toFloat() / length
        features[4] = lower.toFloat() / length
        features[5] = symbol.toFloat() / length
        features[6] = s.toSet().size.toFloat() / length
        features[7] = if (s.all { it in HEX_CHARS }) 1.0f else 0.0f
        features[8] = if (s.all { it in BASE64_CHARS || it == '=' }) 1.0f else 0.0f
        features[9] = if (UUID_PATTERN.matches(s)) 1.0f else 0.0f
        features[10] = if (s.endsWith("=")) 1.0f else 0.0f
        features[11] = if (s.startsWith("\$2a\$") || s.startsWith("\$2b\$") || s.startsWith("\$2y\$")) 1.0f else 0.0f

        if (length >= 3) {
            val invLen = 1.0f / length
            for (i in 0..length - 3) {
                val trigram = s.substring(i, i + 3)
                // trigram.hashCode() is the JVM's documented String.hashCode()
                // formula (h = 31*h + c for each char) -- the exact formula
                // FEATURE_SPEC.md specifies and train_model.py reimplements
                // from scratch on the Python side.
                val bucket = Integer.remainderUnsigned(trigram.hashCode(), TRIGRAM_BUCKETS)
                features[12 + bucket] += invLen
            }
        }

        return features
    }

    /** Same formula as [dev.gaphunter.apisecuritycompanion.detect.SecretDetector.shannonEntropyBitsPerChar]. */
    private fun shannonEntropyBitsPerChar(value: String): Double {
        if (value.isEmpty()) return 0.0
        val counts = value.groupingBy { it }.eachCount()
        val length = value.length.toDouble()
        return -counts.values.sumOf { count ->
            val p = count / length
            p * (Math.log(p) / Math.log(2.0))
        }
    }
}
