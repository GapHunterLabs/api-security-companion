package dev.gaphunter.apisecuritycompanion.detect.ml

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Cross-check against `cross_check_vectors.tsv`, generated once by
 * `ml-training/train_model.py` -- the single mechanical guarantee that
 * [SecretFeatureExtractor] (Kotlin, inference) stays in exact parity
 * with the Python feature extraction used at training time. A future
 * edit to either side that breaks that parity fails this test, instead
 * of silently shipping a classifier that sees different features than
 * the ones it was trained/validated on.
 *
 * Plain tab-separated format (not JSON) deliberately -- no JSON parsing
 * dependency needed on this plugin's plain-JUnit4 test classpath just to
 * read a fixture file. Columns: text \t comma-joined 76 features \t
 * true_label \t sklearn_proba_real_secret.
 */
class SecretFeatureExtractorTest {

    private data class CrossCheckCase(val text: String, val features: List<Double>, val trueLabel: Int, val sklearnProba: Double)

    private fun loadCrossCheckCases(): List<CrossCheckCase> {
        val stream = javaClass.getResourceAsStream("/ml/cross_check_vectors.tsv")
            ?: error("cross_check_vectors.tsv not found on test classpath")
        val cases = mutableListOf<CrossCheckCase>()
        BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).useLines { lines ->
            for (line in lines) {
                if (line.startsWith("#") || line.isBlank()) continue
                val parts = line.split("\t")
                require(parts.size == 4) { "malformed cross-check line: $line" }
                val (text, featStr, labelStr, probaStr) = parts
                val features = featStr.split(",").map { it.toDouble() }
                cases.add(CrossCheckCase(text, features, labelStr.toInt(), probaStr.toDouble()))
            }
        }
        return cases
    }

    @Test
    fun featureDimensionMatchesSpec() {
        assertEquals(76, SecretFeatureExtractor.FEATURE_DIM)
    }

    @Test
    fun everyCrossCheckVectorMatchesWithinFloatTolerance() {
        val cases = loadCrossCheckCases()
        assertTrue("expected at least a few cross-check cases", cases.size >= 10)

        for (case in cases) {
            val actual = SecretFeatureExtractor.extract(case.text)
            assertEquals("feature vector length for '${case.text}'", case.features.size, actual.size)
            for (i in case.features.indices) {
                val expected = case.features[i]
                val diff = Math.abs(expected - actual[i])
                assertTrue(
                    "feature[$i] mismatch for '${case.text}': expected=$expected actual=${actual[i]} diff=$diff",
                    diff < 1e-5,
                )
            }
        }
    }

    // Direct spot checks, independent of the generated fixture -- exercise
    // the deterministic-flag features explicitly by name rather than only
    // through opaque TSV rows.

    @Test
    fun uuidIsFlaggedByUuidDashPattern() {
        val features = SecretFeatureExtractor.extract("a1b2c3d4-e5f6-4789-a123-1234567890ab")
        assertEquals(1.0f, features[9])
    }

    @Test
    fun opaqueTokenIsNotFlaggedByUuidDashPattern() {
        val features = SecretFeatureExtractor.extract("k3j2h4g5f6d7s8a9p0o1i2u3y4t5r6e7w8")
        assertEquals(0.0f, features[9])
    }

    @Test
    fun bcryptPrefixIsFlagged() {
        val features = SecretFeatureExtractor.extract("\$2a\$10\$abcdefghijklmnopqrstuv")
        assertEquals(1.0f, features[11])
    }

    @Test
    fun allHexStringSetsHexFlag() {
        val features = SecretFeatureExtractor.extract("deadbeefcafebabe0123456789abcdef")
        assertEquals(1.0f, features[7])
    }

    @Test
    fun emptyStringReturnsZeroVectorWithoutCrashing() {
        val features = SecretFeatureExtractor.extract("")
        assertEquals(76, features.size)
        assertTrue(features.all { it == 0.0f })
    }
}
