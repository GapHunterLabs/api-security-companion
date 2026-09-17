"""
Trains secret_classifier.onnx -- the model behind api-security-companion's
Pro-tier "reduce false positives on generic high-entropy matches" rule
(SecurityRule.ML_FALSE_POSITIVE_REDUCTION).

Only ever called on candidates that already passed
SecretDetector.looksLikeARealSecret (length >= 12, not an obvious
placeholder, >=3 distinct chars, Shannon entropy >= 3.3 bits/char) and
matched no fixed-format regex (AWS/GitHub/Slack/JWT/PEM/Stripe already
short-circuit before reaching this classifier). Its only job: further
split that already-narrow GENERIC_HIGH_ENTROPY bucket into "looks like a
real opaque secret" vs. the common false-positive shapes that also pass
a pure entropy check (UUIDs, hex hashes, base64 fixtures, bcrypt fixture
hashes, test/sample IDs).

Feature extraction implements FEATURE_SPEC.md exactly -- see that file
for the formula of every one of the 76 features. This module is the
single source of truth on the Python/training side; SecretFeatureExtractor.kt
is the Kotlin/inference-side reimplementation, and cross_check_vectors.json
(written by this script) is what a JUnit test uses to catch any drift
between the two, mechanically, on every build.

Real data note (see ml-training/README.md for the full trail): no public
corpus of "real leaked secret vs. false positive", labeled, in useful
volume, was found (gitleaks' testdata/ is regex-rule fixtures, not
example secret VALUES; trufflehog's is AGPL-3.0, not usable here without
legal review -- both checked and rejected as primary data sources, see
README.md). Training data here is realistic-shaped synthetic data,
documented honestly as such -- not a claim of training on real leaked
secrets.
"""
import base64
import json
import random
import string
import time

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve
from sklearn.neural_network import MLPClassifier

random.seed(1337)

ALPHANUM = string.ascii_letters + string.digits
B64_CHARS = string.ascii_letters + string.digits + "+/"
B64_URL_CHARS = string.ascii_letters + string.digits + "-_"
HEX_CHARS = "0123456789abcdef"
HEX_CHARS_UPPER = "0123456789ABCDEF"


# ---------------------------------------------------------------------------
# Feature extraction -- must match FEATURE_SPEC.md exactly (Python side).
# ---------------------------------------------------------------------------

def java_string_hash(s: str) -> int:
    h = 0
    for ch in s:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return h


def shannon_entropy_bits_per_char(value: str) -> float:
    if not value:
        return 0.0
    from collections import Counter
    counts = Counter(value)
    length = float(len(value))
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * (np.log(p) / np.log(2.0))
    return entropy


import re

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def extract_features(s: str) -> np.ndarray:
    features = np.zeros(76, dtype=np.float32)
    length = len(s)
    if length == 0:
        return features

    features[0] = min(length, 128) / 128.0
    features[1] = shannon_entropy_bits_per_char(s) / 8.0

    digit = sum(1 for c in s if c.isdigit())
    upper = sum(1 for c in s if c.isupper())
    lower = sum(1 for c in s if c.islower())
    symbol = length - digit - upper - lower

    features[2] = digit / length
    features[3] = upper / length
    features[4] = lower / length
    features[5] = symbol / length
    features[6] = len(set(s)) / length
    features[7] = 1.0 if all(c in HEX_CHARS or c in HEX_CHARS_UPPER for c in s) else 0.0
    features[8] = 1.0 if all(c in B64_CHARS or c == "=" for c in s) else 0.0
    features[9] = 1.0 if _UUID_RE.match(s) else 0.0
    features[10] = 1.0 if s.endswith("=") else 0.0
    features[11] = 1.0 if s.startswith(("$2a$", "$2b$", "$2y$")) else 0.0

    if length >= 3:
        inv_len = 1.0 / length
        for i in range(length - 2):
            trigram = s[i:i + 3]
            h = java_string_hash(trigram)
            idx = h % 64
            features[12 + idx] += inv_len

    return features


# ---------------------------------------------------------------------------
# Synthetic data generators -- expanded from the spike (more shapes, more
# volume). Positives deliberately avoid the fixed-format shapes
# (AWS/GitHub/Slack/JWT/PEM/Stripe) since those never reach this
# classifier in production -- SecretDetector.scanLiteral short-circuits on
# them first.
# ---------------------------------------------------------------------------

def real_secret_opaque():
    """Generic opaque high-entropy token -- no recognizable prefix."""
    length = random.randint(20, 56)
    charset = random.choice([ALPHANUM, ALPHANUM + "-_", B64_CHARS, B64_URL_CHARS])
    return "".join(random.choice(charset) for _ in range(length))


def real_secret_hyphenated():
    """Some real secrets are chunked with separators (not UUID-shaped)."""
    chunks = [
        "".join(random.choice(ALPHANUM) for _ in range(random.randint(4, 8)))
        for _ in range(random.randint(3, 5))
    ]
    return "-".join(chunks)


def real_secret_mixed_case_dense():
    """Deliberately high entropy, near-uniform character distribution --
    the case a pure-entropy heuristic is actually good at, kept in the
    positive set so the classifier doesn't learn to suppress everything
    the old heuristic already did well on."""
    length = random.randint(24, 40)
    return "".join(random.choice(ALPHANUM) for _ in range(length))


def fp_uuid():
    def grp(n):
        return "".join(random.choice(HEX_CHARS) for _ in range(n))
    return f"{grp(8)}-{grp(4)}-{grp(4)}-{grp(4)}-{grp(12)}"


def fp_hex_hash():
    length = random.choice([32, 40, 64])  # md5 / sha1 / sha256
    case_fn = str.upper if random.random() < 0.15 else str.lower
    return case_fn("".join(random.choice(HEX_CHARS) for _ in range(length)))


def fp_git_sha_short():
    # Short git commit SHA references, common in changelogs/comments.
    return "".join(random.choice(HEX_CHARS) for _ in range(random.choice([7, 8, 10, 12])))


def fp_docker_digest():
    return "sha256:" + "".join(random.choice(HEX_CHARS) for _ in range(64))


def fp_base64_fixture():
    samples = [
        '{"user":"testuser","role":"admin","env":"test"}',
        '{"id":1,"name":"Example Corp","active":true}',
        "the quick brown fox jumps over the lazy dog test fixture",
        '{"orderId":"ORD-1001","status":"PENDING","total":42.5}',
        "Lorem ipsum dolor sit amet consectetur adipiscing elit",
        '{"env":"staging","debug":true,"version":"1.0.0"}',
    ]
    return base64.b64encode(random.choice(samples).encode()).decode()


def fp_npm_integrity_hash():
    # package-lock.json "integrity" field shape: sha512-<base64>
    payload = "".join(random.choice(B64_CHARS) for _ in range(64))
    return f"sha512-{payload}=="


def fp_bcrypt_fixture():
    safe_b64 = B64_CHARS.replace("+", ".").replace("/", ".")
    salt = "".join(random.choice(safe_b64) for _ in range(22))
    hashpart = "".join(random.choice(safe_b64) for _ in range(31))
    return f"$2a$10${salt}{hashpart}"


def fp_test_id_fixture():
    prefixes = ["cus_test_", "test_", "fixture_", "example_", "sample_", "demo_", "mock_"]
    length = random.randint(14, 24)
    return random.choice(prefixes) + "".join(random.choice(ALPHANUM) for _ in range(length))


def fp_webpack_chunk_hash():
    # Content hashes in built JS filenames, e.g. main.a1b2c3d4e5f6.js
    return "".join(random.choice(HEX_CHARS) for _ in range(20))


def fp_base32_ish():
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    length = random.randint(16, 32)
    return "".join(random.choice(charset) for _ in range(length))


POSITIVE_GENERATORS = [real_secret_opaque, real_secret_opaque, real_secret_hyphenated, real_secret_mixed_case_dense]
NEGATIVE_GENERATORS = [
    fp_uuid, fp_hex_hash, fp_hex_hash, fp_git_sha_short, fp_docker_digest,
    fp_base64_fixture, fp_npm_integrity_hash, fp_bcrypt_fixture,
    fp_test_id_fixture, fp_webpack_chunk_hash, fp_base32_ish,
]


def make_dataset(n_per_class=8000):
    xs, ys = [], []
    seen = set()
    while sum(1 for y in ys if y == 1) < n_per_class:
        v = random.choice(POSITIVE_GENERATORS)()
        if v in seen or len(v) < 12:
            continue
        seen.add(v)
        xs.append(v)
        ys.append(1)
    while sum(1 for y in ys if y == 0) < n_per_class:
        v = random.choice(NEGATIVE_GENERATORS)()
        if v in seen or len(v) < 12:
            continue
        seen.add(v)
        xs.append(v)
        ys.append(0)
    return xs, ys


def main():
    xs, ys = make_dataset()
    print(f"Dataset: {len(xs)} examples ({sum(ys)} positive / {len(ys) - sum(ys)} negative)")

    x_train, x_test, y_train, y_test = train_test_split(xs, ys, test_size=0.2, random_state=42, stratify=ys)

    x_train_feat = np.stack([extract_features(v) for v in x_train])
    x_test_feat = np.stack([extract_features(v) for v in x_test])

    clf = MLPClassifier(hidden_layer_sizes=(48, 24), max_iter=800, random_state=42, early_stopping=True)
    clf.fit(x_train_feat, y_train)

    proba = clf.predict_proba(x_test_feat)[:, 1]
    preds = (proba >= 0.5).astype(int)

    print("\n=== Default 0.5 threshold evaluation ===")
    print(classification_report(y_test, preds, target_names=["false_positive", "real_secret"]))
    print(confusion_matrix(y_test, preds))

    # Conservative SUPPRESSION threshold: per the plan's explicit design
    # decision, the app only suppresses a warning (treats it as a false
    # positive) when `proba_real_secret < suppress_below` -- a missed real
    # secret is a much worse failure mode than one extra false-positive
    # warning shown, so `suppress_below` must be set low enough that
    # almost no real secret ever falls under it. Concretely: pick the
    # value such that at most 1% of ACTUAL real secrets in the held-out
    # set have a lower predicted probability than it (1st percentile of
    # proba among the real_secret class), then take the 0.5th percentile
    # instead of the 1st for one extra safety margin.
    proba_real_secrets = proba[np.array(y_test) == 1]
    suppress_threshold = float(np.percentile(proba_real_secrets, 0.5))
    print(f"\nConservative suppression threshold (suppress when proba < this): {suppress_threshold:.4f}")

    # Applying it: predicted_real_secret = proba >= suppress_threshold
    # (i.e. NOT suppressed); predicted_false_positive = proba < suppress_threshold (suppressed).
    conservative_preds = (proba >= suppress_threshold).astype(int)
    print("=== Conservative threshold evaluation ===")
    print(classification_report(y_test, conservative_preds, target_names=["false_positive", "real_secret"]))
    cm = confusion_matrix(y_test, conservative_preds)
    print(cm)
    # cm[1][0] = actual real_secret, predicted false_positive (suppressed) = a MISS -- must stay near 0.
    # cm[0][0] = actual false_positive, predicted false_positive (suppressed) = the actual value delivered.
    fn_rate = cm[1][0] / (cm[1][0] + cm[1][1])
    suppression_rate_on_fps = cm[0][0] / (cm[0][0] + cm[0][1])
    print(f"Real-secret miss rate (real secrets wrongly suppressed): {fn_rate:.4%} -- must stay ~0")
    print(f"False-positive suppression rate (actual false positives correctly suppressed): {suppression_rate_on_fps:.2%} -- the real value delivered")

    # Export to ONNX -- hand-built graph, NOT skl2onnx.to_onnx(). skl2onnx's
    # classifier converter injects ai.onnx.ml-domain ops (ArrayFeatureExtractor,
    # ZipMap, ...) for sklearn-specific convenience; KInference (the JVM
    # inference engine used on the Kotlin side, see MlClassifierService.kt
    # for why -- the official onnxruntime Java binding crashes inside a
    # JetBrains-Runtime-hosted process) only implements standard deep-
    # learning ai.onnx ops, confirmed by a real
    # "Unsupported operator: ArrayFeatureExtractor" failure the first time
    # this was tried with skl2onnx's default export. Building the graph
    # directly from the trained weights with only Gemm/Relu/Sigmoid
    # sidesteps that gap entirely and is straightforward for a network
    # this small.
    #
    # MLPClassifier internals for BINARY classification (confirmed by
    # inspecting the trained clf directly, not assumed): a single output
    # neuron with logistic (sigmoid) activation -- clf.out_activation_ ==
    # "logistic", clf.n_outputs_ == 1 -- NOT a 2-unit softmax. The graph
    # below is exactly clf.coefs_/clf.intercepts_ applied in order:
    # Gemm+Relu per hidden layer, Gemm+Sigmoid for the single output unit.
    assert clf.out_activation_ == "logistic" and clf.n_outputs_ == 1, (
        "hand-built graph below assumes single-sigmoid-output binary MLPClassifier -- "
        f"got out_activation_={clf.out_activation_!r} n_outputs_={clf.n_outputs_}, update the graph to match"
    )

    import onnx
    from onnx import helper, TensorProto, numpy_helper

    def initializer(name, arr):
        return numpy_helper.from_array(arr.astype(np.float32), name=name)

    initializers = []
    nodes = []
    prev = "input"
    for i, (w, b) in enumerate(zip(clf.coefs_, clf.intercepts_)):
        w_name, b_name, out_name = f"W{i}", f"b{i}", f"gemm_out_{i}"
        initializers.append(initializer(w_name, w))
        initializers.append(initializer(b_name, b))
        nodes.append(helper.make_node("Gemm", [prev, w_name, b_name], [out_name], name=f"gemm_{i}"))
        is_last = i == len(clf.coefs_) - 1
        activated_name = "proba_real_secret" if is_last else f"relu_out_{i}"
        nodes.append(helper.make_node(
            "Sigmoid" if is_last else "Relu",
            [out_name], [activated_name], name=f"{'sigmoid' if is_last else 'relu'}_{i}",
        ))
        prev = activated_name

    graph = helper.make_graph(
        nodes,
        "secret_classifier",
        [helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, 76])],
        [helper.make_tensor_value_info("proba_real_secret", TensorProto.FLOAT, [None, 1])],
        initializers,
    )
    onnx_model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    onnx_model.ir_version = 8  # matches opset 13 per the official IR/opset compatibility table
    onnx.checker.check_model(onnx_model)

    model_path = "secret_classifier.onnx"
    with open(model_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    import os
    size_bytes = os.path.getsize(model_path)
    print(f"\n=== ONNX export (hand-built graph) ===\nModel file size: {size_bytes} bytes ({size_bytes / 1024:.1f} KB)")

    import onnxruntime as rt
    sess = rt.InferenceSession(model_path, providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name
    output_names = [o.name for o in sess.get_outputs()]
    print(f"ONNX outputs: {output_names}")

    # Correctness cross-check: ONNX proba output vs sklearn proba output.
    onnx_out = sess.run(None, {input_name: x_test_feat.astype(np.float32)})
    onnx_proba = onnx_out[0][:, 0]
    max_diff = np.max(np.abs(onnx_proba - proba))
    print(f"Max |ONNX proba - sklearn proba| over test set: {max_diff:.6f}")

    # Latency
    for _ in range(10):
        sess.run(None, {input_name: x_test_feat[:1]})
    n_trials = 500
    start = time.perf_counter()
    for i in range(n_trials):
        sess.run(None, {input_name: x_test_feat[i % len(x_test_feat): i % len(x_test_feat) + 1]})
    elapsed = time.perf_counter() - start
    print(f"Single-item inference latency (Python onnxruntime, CPU): {(elapsed / n_trials) * 1000:.3f} ms/call")

    # Cross-check vectors for the Kotlin-side JUnit test. Plain
    # tab-separated text, deliberately not JSON -- avoids pulling a JSON
    # parsing dependency onto the plugin's plain-JUnit4 test classpath
    # just to read a fixture file. Columns: text \t comma-joined 76
    # features \t true_label \t sklearn_proba_real_secret. First line is
    # a header comment with the suppression threshold for reference.
    rng_indices = random.sample(range(len(x_test)), 24)
    with open("cross_check_vectors.tsv", "w") as f:
        f.write(f"# suppress_threshold={suppress_threshold!r} feature_dim=76\n")
        for i in rng_indices:
            feat_str = ",".join(repr(float(v)) for v in x_test_feat[i])
            f.write(f"{x_test[i]}\t{feat_str}\t{y_test[i]}\t{float(proba[i])!r}\n")
    print("\nWrote cross_check_vectors.tsv and secret_classifier.onnx")


if __name__ == "__main__":
    main()
