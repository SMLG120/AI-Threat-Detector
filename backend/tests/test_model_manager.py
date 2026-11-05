import pickle

import numpy as np
import pytest

from ml.model_manager import ModelManager
from pipeline.feature_extractor import FEATURE_NAMES


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    d = tmp_path_factory.mktemp("models")
    mm = ModelManager(model_dir=str(d))
    mm.bootstrap(save=True)
    return mm


def test_bootstrap_saves_bundle(trained):
    assert trained.bundle_path.exists()
    assert trained.is_ready
    assert not list(trained.model_dir.glob(".ensemble-*.tmp"))  # no temp leftovers


def test_load_and_predict(trained):
    mm = ModelManager(model_dir=str(trained.model_dir))
    assert mm.load_models(bootstrap_if_missing=False)
    scores = mm.predict(np.zeros(len(FEATURE_NAMES), dtype=np.float32))
    assert set(scores) == {"isolation_forest", "random_forest", "autoencoder"}
    assert all(0.0 <= v <= 1.0 for v in scores.values())


def test_malicious_vector_scores_higher(trained):
    benign = np.full(len(FEATURE_NAMES), 0.1, dtype=np.float32)
    malicious = benign.copy()
    malicious[10:15] = 0.9
    malicious[7:10] = 0.8
    assert trained.predict(malicious)["random_forest"] > trained.predict(benign)["random_forest"]


def test_missing_bundle_without_bootstrap(tmp_path):
    mm = ModelManager(model_dir=str(tmp_path))
    assert mm.load_models(bootstrap_if_missing=False) is False
    assert not mm.is_ready


def test_reload_rejects_mismatched_features_and_keeps_current(trained, tmp_path):
    mm = ModelManager(model_dir=str(tmp_path))
    mm.save(trained.bundle)
    good_version = mm.version

    bad = pickle.loads(pickle.dumps(trained.bundle))
    bad.feature_names = ["something_else"]
    bad.version = "bad"
    with open(mm.bundle_path, "wb") as f:
        pickle.dump(bad, f)

    assert mm.reload() is False
    assert mm.version == good_version
