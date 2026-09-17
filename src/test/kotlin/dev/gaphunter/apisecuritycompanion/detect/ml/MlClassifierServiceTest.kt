package dev.gaphunter.apisecuritycompanion.detect.ml

import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Loads the real bundled `secret_classifier.onnx` directly (not a mock)
 * and exercises it against known-shape inputs -- this is the actual
 * model that ships, so a real regression in training data/threshold
 * shows up here, not just in the Python-side report.
 *
 * Constructed directly (not via [MlClassifierService.getInstance], which
 * needs a running platform `service()` container) -- consistent with
 * this codebase's convention of testing pure/service logic without a
 * platform fixture whenever the logic itself doesn't touch PSI/project
 * state (see `SecretDetectorTest.kt`).
 */
class MlClassifierServiceTest {

    private val classifier = MlClassifierService()

    @After
    fun tearDown() {
        classifier.dispose()
    }

    @Test
    fun clearFalsePositiveShapesAreSuppressed() {
        // UUID -- a classic GENERIC_HIGH_ENTROPY false positive: high
        // entropy, no recognized secret format, but not a real secret.
        assertTrue(classifier.isConfidentFalsePositive("a1b2c3d4-e5f6-4789-a123-1234567890ab"))
        // sha256 hex hash.
        assertTrue(classifier.isConfidentFalsePositive("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        // test/sample fixture ID -- taken directly from
        // ml-training/cross_check_vectors.tsv (a real held-out example,
        // sklearn_proba_real_secret=0.034, well under the 0.0854
        // suppression threshold), not hand-picked blind: an earlier
        // hand-picked example of this same shape
        // ("test_k3j2h4g5f6d7s8a9p0o1i2u3") turned out to be a genuine
        // borderline case the model doesn't confidently catch (proba
        // ~0.3-0.5 for some test_/sample_/demo_ instances per the
        // held-out set) -- expected given the measured 95.19% (not
        // 100%) false-positive suppression rate at this threshold, not
        // a bug. Picking directly from validated held-out data avoids
        // asserting on an unverified guess of what the model does.
        assertTrue(classifier.isConfidentFalsePositive("sample_QsXyJgqoR0C0mZCEu2vYl"))
    }

    @Test
    fun opaqueHighEntropyTokensAreNotSuppressed() {
        // Dense, mixed-case, no recognizable structure -- exactly what a
        // real generic secret looks like, and exactly the case that must
        // NEVER be suppressed (a real-secret miss here means a real leak
        // goes unflagged).
        assertFalse(classifier.isConfidentFalsePositive("k3nS8dQ7pL2xM9vB4tR6yU1wZ5aC0fH8jN3g"))
        assertFalse(classifier.isConfidentFalsePositive("Xq7-mK2-bV9-pL4-jR8-nT3-wY6"))
    }

    @Test
    fun emptyOrTrivialInputNeverThrowsAndFailsOpen() {
        // Fails open (returns false, i.e. "not confidently a false
        // positive", i.e. keep the warning) on degenerate input rather
        // than throwing -- checked directly since SecretDetector's own
        // length>=12 gate normally prevents this input shape from ever
        // reaching this classifier in production, but the classifier
        // itself must not assume that gate always ran first.
        assertFalse(classifier.isConfidentFalsePositive(""))
        assertFalse(classifier.isConfidentFalsePositive("short"))
    }
}
