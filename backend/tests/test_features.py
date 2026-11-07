import numpy as np

from pipeline.feature_extractor import (
    FEATURE_NAMES,
    RawRequest,
    extract_features,
    features_dict_to_array,
)


def _req(url="https://example.com/a?b=c", body=""):
    return RawRequest(ip_address="1.2.3.4", method="GET", url=url, request_body=body)


def test_feature_count_is_stable():
    assert len(FEATURE_NAMES) == 29


def test_vector_matches_stored_dict_roundtrip():
    fv = extract_features(_req("https://x.com/p?id=1 UNION SELECT 1"))
    stored = fv.model_dump()  # what's persisted to the DB JSON column
    # Reorder keys to prove order in storage doesn't matter
    shuffled = dict(reversed(list(stored.items())))
    np.testing.assert_allclose(features_dict_to_array(shuffled), fv.to_numpy())


def test_attack_raises_pattern_scores():
    benign = extract_features(_req("https://x.com/search?q=shoes"))
    attack = extract_features(_req("https://x.com/search?q=' OR 1=1--"))
    assert attack.sql_pattern_score > benign.sql_pattern_score
