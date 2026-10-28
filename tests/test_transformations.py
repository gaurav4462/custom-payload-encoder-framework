
import pytest

from obfuscation.strings import (
    escape_representation,
    restore_escape_representation,
)

from encoder.transformations import (
    base64_encode,
    base64_decode,
    rot13_transform,
    xor_transform,
    xor_reverse,
)
from obfuscation.strings import (
    split_string,
    reconstruct_string,
)
from detection.signatures import analyze_sample
from evaluation.metrics import calculate_metrics


def test_base64_round_trip():
    original = "Hello, cybersecurity!"
    assert base64_decode(base64_encode(original)) == original


def test_rot13_round_trip():
    original = "HELLO WORLD"
    assert rot13_transform(rot13_transform(original)) == original


def test_xor_round_trip():
    original = "Hello, cybersecurity!"
    transformed = xor_transform(original, "test-key")
    assert xor_reverse(transformed, "test-key") == original


def test_empty_xor_key_is_rejected():
    with pytest.raises(ValueError):
        xor_transform("hello", "")


def test_split_and_reconstruct():
    original = "HELLOWORLD"
    assert reconstruct_string(split_string(original, 3)) == original


def test_invalid_chunk_size():
    with pytest.raises(ValueError):
        split_string("hello", 0)


def test_original_training_marker_is_detected():
    result = analyze_sample("TRAINING-DEMO-MARKER")
    assert result["raw_detected"] is True
    assert result["normalized_detected"] is True


def test_base64_marker_is_detected_after_normalization():
    encoded = base64_encode("TRAINING-DEMO-MARKER")
    result = analyze_sample(encoded, encoding="base64")
    assert result["raw_detected"] is False
    assert result["normalized_detected"] is True


def test_metrics():
    result = calculate_metrics(8, 2, 9, 1)
    assert result["precision"] == pytest.approx(8 / 10)
    assert result["recall"] == pytest.approx(8 / 9)


def test_negative_metrics_counts_are_rejected():
    with pytest.raises(ValueError):
        calculate_metrics(-1, 0, 0, 0)


def test_escape_representation_round_trip():
    original = "Hello\nWorld\t!"
    escaped = escape_representation(original)

    assert restore_escape_representation(escaped) == original


def test_escape_representation_with_unicode():
    original = "Hello café 😊"

    escaped = escape_representation(original)

    assert restore_escape_representation(escaped) == original


def test_invalid_escape_representation():
    with pytest.raises(ValueError):
        restore_escape_representation("not a valid string literal")