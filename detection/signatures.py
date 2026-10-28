
from encoder.transformations import (
    base64_decode,
    rot13_transform,
    xor_reverse,
)


# Harmless marker used only in the local training exercise.
SIGNATURES = ["TRAINING-DEMO-MARKER"]


def detect(text: str) -> list[str]:
    """Find known training markers using case-sensitive matching."""
    return [
        signature
        for signature in SIGNATURES
        if signature in text
    ]


def normalize_sample(
    text: str,
    encoding: str = "none",
    xor_key: str = "",
) -> str:
    """
    Decode one explicitly selected representation.
    Does not execute or load the resulting text.
    """
    if encoding == "none":
        return text

    if encoding == "base64":
        return base64_decode(text)

    if encoding == "rot13":
        return rot13_transform(text)

    if encoding == "xor_hex":
        return xor_reverse(text, xor_key)

    raise ValueError(f"Unsupported encoding: {encoding}")


def analyze_sample(
    text: str,
    encoding: str = "none",
    xor_key: str = "",
) -> dict:
    """Compare raw matching with matching after normalization."""
    raw_matches = detect(text)

    try:
        normalized = normalize_sample(text, encoding, xor_key)
        normalized_matches = detect(normalized)
        error = None
    except (ValueError, UnicodeError) as exc:
        normalized = None
        normalized_matches = []
        error = str(exc)

    return {
        "raw_detected": bool(raw_matches),
        "raw_matches": raw_matches,
        "normalized_detected": bool(normalized_matches),
        "normalized_matches": normalized_matches,
        "normalization_error": error,
    }
