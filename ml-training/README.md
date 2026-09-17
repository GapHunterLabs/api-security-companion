# ML training — SecurityRule.ML_FALSE_POSITIVE_REDUCTION

Trains and exports `secret_classifier.onnx`, the model behind
`api-security-companion`'s optional Pro rule that reduces false
positives on `SecretDetector`'s generic, Shannon-entropy-based
`GENERIC_HIGH_ENTROPY` case (never on a recognized signature/format
like an AWS key or a JWT — those short-circuit before reaching this
classifier at all).

## Files

- `FEATURE_SPEC.md` — the exact, formula-level spec for how a
  candidate string becomes a 76-value feature vector. Implemented
  twice: here in Python (training) and in
  `src/main/kotlin/.../detect/ml/SecretFeatureExtractor.kt`
  (inference). Both MUST produce byte-identical output for the same
  input — read this file before touching either implementation.
- `train_model.py` — generates training data, trains the classifier,
  and exports `secret_classifier.onnx` + `cross_check_vectors.tsv`.
- `secret_classifier.onnx` — the trained model, hand-built as a raw
  `Gemm`/`Relu`/`Sigmoid` graph (see "Why a hand-built ONNX graph"
  below) — **copy this to `src/main/resources/ml/secret_classifier.onnx`**
  after retraining, it is not read from here at runtime.
- `cross_check_vectors.tsv` — 24 held-out examples with their expected
  feature vectors and model output, used by
  `SecretFeatureExtractorTest.kt` to catch any drift between the
  Python and Kotlin feature-extraction implementations. **Copy this to
  `src/test/resources/ml/cross_check_vectors.tsv`** after retraining,
  same reason.

## Running it

```
pip install scikit-learn skl2onnx onnx onnxruntime numpy
python train_model.py
cp secret_classifier.onnx ../src/main/resources/ml/secret_classifier.onnx
cp cross_check_vectors.tsv ../src/test/resources/ml/cross_check_vectors.tsv
```

Then from the plugin root: `./gradlew test` (checks the new fixture
against the Kotlin feature extractor and the bundled model) and
`./gradlew buildPlugin` to confirm the new model is picked up.

## Training data — honestly, what it is and isn't

There is no public corpus of "real leaked secret vs. false positive,"
labeled, in useful volume. Two real candidates were checked and
rejected as primary data sources:

- **gitleaks** (`gitleaks/gitleaks`, MIT license — confirmed by
  reading `LICENSE` directly): its `testdata/` folder is detection
  *rule* fixtures (regexes for its own test suite), not example secret
  *values* — not usable as training data at all.
- **trufflehog** (`trufflesecurity/trufflehog`): AGPL-3.0 (confirmed
  by reading `LICENSE`) — a real licensing risk for training a model
  distributed inside a commercial Apache-2.0 plugin. Not used.

The dataset in `train_model.py` is realistic-shaped **synthetic**
data: positives are opaque high-entropy tokens (the actual shape a
generic leaked secret has); negatives are the common false-positive
shapes that also pass a pure entropy check — UUIDs, hex hashes, git
SHAs, Docker digests, base64-encoded test fixtures, npm integrity
hashes, bcrypt fixture hashes, and `test_`/`sample_`/`fixture_`-style
IDs. This is documented here explicitly so nobody mistakes the
accuracy numbers `train_model.py` prints for a real-world, audited
benchmark — they're a held-out split of the same synthetic
generators, useful for catching regressions, not a claim about
production performance.

## Why a hand-built ONNX graph, not `skl2onnx.to_onnx()`

The default scikit-learn → ONNX exporter injects `ai.onnx.ml`-domain
operators (`ArrayFeatureExtractor`, `ZipMap`) for classifier
convenience, on top of the actual neural network. KInference (the
pure-JVM inference engine used on the Kotlin side — see
`MlClassifierService.kt` for why not the official
`com.microsoft.onnxruntime` Java binding, which crashes inside a
JetBrains-Runtime-hosted process) only implements standard
deep-learning `ai.onnx` operators, confirmed by a real
`Unsupported operator: ArrayFeatureExtractor` failure the first time
this was tried with the default exporter.

`train_model.py` instead pulls the trained `MLPClassifier`'s raw
`coefs_`/`intercepts_` and builds the graph directly with `onnx.helper`,
using only `Gemm`/`Relu` per hidden layer and a final `Gemm`/`Sigmoid`
(binary classification here is a single sigmoid output unit, not a
2-unit softmax — confirmed on the trained model:
`out_activation_ == "logistic"`, `n_outputs_ == 1`, not assumed).
Small network, so this is a straightforward, fully-controlled
alternative to guessing which exporter flags might avoid the
unsupported ops.

## Retraining checklist

1. Change generators/data/architecture in `train_model.py` as needed.
2. Run it — read the printed real-secret miss rate (must stay ~0%,
   never trade it away for a higher suppression rate: see
   `MlClassifierService.kt`'s conservative-threshold design) and the
   ONNX/sklearn/JVM correctness cross-checks.
3. Copy both output files into the plugin's resource dirs (paths
   above).
4. Update the hardcoded `suppressBelowThreshold` constant in
   `MlClassifierService.kt` to match the new threshold printed by the
   script — it is not read from the model or a config file, it's a
   literal that must be kept in sync by hand.
5. `./gradlew test` and `./gradlew buildPlugin` before considering it done.
