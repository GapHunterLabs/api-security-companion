package dev.gaphunter.apisecuritycompanion.detect.ml

import com.intellij.openapi.Disposable
import com.intellij.openapi.components.service
import com.intellij.openapi.diagnostic.Logger
import io.kinference.core.KIEngine
import io.kinference.core.data.tensor.asTensor
import io.kinference.core.model.KIModel
import io.kinference.ndarray.arrays.FloatNDArray
import io.kinference.utils.PredictionConfigs
import io.kinference.utils.inlines.InlineInt
import kotlinx.coroutines.runBlocking

/**
 * Application-level service behind `SecurityRule.ML_FALSE_POSITIVE_REDUCTION`
 * (Pro, off by default -- see [dev.gaphunter.apisecuritycompanion.settings.SecurityRule]
 * for why this one rule breaks from "everything enabled by default").
 *
 * Loads `secret_classifier.onnx` (bundled as a plugin resource, 20KB --
 * see `ml-training/README.md` for how it was trained) once, lazily, only
 * the first time a licensed user with the rule enabled actually hits a
 * `GENERIC_HIGH_ENTROPY` candidate -- never eagerly at plugin startup,
 * so free-tier/unlicensed users never pay the classload/model-load cost
 * even though the dependency ships in every install.
 *
 * Runs inference via KInference (pure-JVM ONNX engine), not the official
 * `com.microsoft.onnxruntime` Java binding -- that native binding
 * crashes the JVM with `EXCEPTION_ACCESS_VIOLATION` the instant it
 * initializes inside a JetBrains-Runtime-hosted process (confirmed via a
 * real crash: `onnxruntime.dll` collides with JBR's own bundled, and
 * apparently incompatible, `msvcp140.dll`). KInference has no native
 * library at all, so this entire class of bug cannot occur.
 *
 * The bundled model's ONNX graph is hand-built in `ml-training/train_model.py`
 * (`Gemm`/`Relu`/`Sigmoid` only), not the default `skl2onnx` classifier
 * export -- KInference doesn't implement the `ai.onnx.ml`-domain ops
 * (`ArrayFeatureExtractor`, `ZipMap`, ...) that converter injects
 * (confirmed by a real `Unsupported operator: ArrayFeatureExtractor`
 * failure). The graph's single output, `proba_real_secret`
 * (shape `[N, 1]`), is the raw sigmoid output of the trained
 * `MLPClassifier`'s single output unit -- binary classification here
 * uses one sigmoid unit, not a 2-unit softmax (confirmed on the trained
 * model: `out_activation_ == "logistic"`, `n_outputs_ == 1`).
 *
 * Fails open on every error path (model missing, load failure, inference
 * exception): this feature only ever REMOVES a warning the base
 * heuristic already decided to show, so any failure here must fall back
 * to "keep showing the warning", never the reverse.
 */
class MlClassifierService : Disposable {
    private val logger = Logger.getInstance(MlClassifierService::class.java)

    // Suppress a GENERIC_HIGH_ENTROPY warning only when the model is
    // confident this candidate is NOT a real secret (predicted
    // probability of being a real secret is below this value). Derived
    // in ml-training/train_model.py as the 0.5th percentile of
    // P(real_secret) over the real_secret class on held-out data --
    // i.e., on that evaluation, suppressing at this threshold wrongly
    // silenced at most ~0.5% of actual real secrets. A missed real
    // secret is a far worse outcome than one extra warning shown, so
    // this stays deliberately conservative -- never raise it without
    // re-validating the real-secret miss rate on a held-out set.
    private val suppressBelowThreshold = 0.08538591116666794f

    private val model: KIModel? by lazy { loadModel() }

    private fun loadModel(): KIModel? {
        return try {
            val modelBytes = javaClass.getResourceAsStream("/ml/secret_classifier.onnx")?.readBytes()
            if (modelBytes == null) {
                logger.warn("secret_classifier.onnx resource not found -- ML false-positive reduction disabled")
                return null
            }
            runBlocking { KIEngine.loadModel(modelBytes, optimize = true, predictionConfig = PredictionConfigs.DefaultAutoAllocator) }
        } catch (e: Throwable) {
            logger.warn("Failed to load ML false-positive reduction model, feature disabled", e)
            null
        }
    }

    /**
     * @return true only when confident [value] is a false positive of the
     * GENERIC_HIGH_ENTROPY heuristic, not a real secret. Any failure
     * (model unavailable, inference error) returns false -- fail open,
     * keep the original warning.
     */
    fun isConfidentFalsePositive(value: String): Boolean {
        // Defense in depth: the model was only ever trained on
        // GENERIC_HIGH_ENTROPY candidates, which SecretDetector's own
        // length>=12 gate (MIN_ENTROPY_LENGTH in SecretDetector.kt)
        // already guarantees upstream in production. Don't trust that
        // upstream gate blindly here too -- a degenerate near-empty
        // input is out-of-distribution for the model (never seen
        // anything that short during training) and its output on it is
        // unverified, not a real guarantee either way.
        if (value.length < 12) return false
        val activeModel = model ?: return false
        return try {
            val features = SecretFeatureExtractor.extract(value)
            val probaRealSecret = runBlocking {
                val inputArray = FloatNDArray(intArrayOf(1, SecretFeatureExtractor.FEATURE_DIM)) { index: InlineInt -> features[index.value] }
                val inputTensor = inputArray.asTensor("input")
                val outputs = activeModel.predict(listOf(inputTensor))
                val output = outputs["proba_real_secret"]?.data as? FloatNDArray ?: return@runBlocking null
                output.array.toArray()[0]
            } ?: return false
            probaRealSecret < suppressBelowThreshold
        } catch (e: Throwable) {
            logger.warn("ML false-positive classification failed for a candidate, failing open (keeping the warning)", e)
            false
        }
    }

    override fun dispose() {
        model?.close()
    }

    companion object {
        fun getInstance(): MlClassifierService = service()
    }
}
