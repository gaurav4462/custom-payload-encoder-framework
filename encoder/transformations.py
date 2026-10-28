
import base64
import codecs


def base64_encode(text: str) -> str:
    """Encode text as Base64."""
    raw = text.encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def base64_decode(encoded: str) -> str:
    """Decode valid Base64 text into UTF-8."""
    raw = base64.b64decode(encoded, validate=True)
    return raw.decode("utf-8")


def rot13_transform(text: str) -> str:
    """Apply ROT13. Applying it twice restores the text."""
    return codecs.encode(text, "rot_13")


def xor_transform(text: str, key: str) -> str:
    """
    Apply a reversible XOR transformation to UTF-8 text.
    Return the result as hexadecimal so arbitrary bytes are representable.
    """
    if not key:
        raise ValueError("The XOR key must not be empty.")

    data = text.encode("utf-8")
    key_bytes = key.encode("utf-8")

    transformed = bytes(
        byte ^ key_bytes[i % len(key_bytes)]
        for i, byte in enumerate(data)
    )

    return transformed.hex()


def xor_reverse(hex_data: str, key: str) -> str:
    """Reverse the XOR transformation from hexadecimal input."""
    if not key:
        raise ValueError("The XOR key must not be empty.")

    try:
        data = bytes.fromhex(hex_data)
    except ValueError as exc:
        raise ValueError("Input must be valid hexadecimal.") from exc

    key_bytes = key.encode("utf-8")

    restored = bytes(
        byte ^ key_bytes[i % len(key_bytes)]
        for i, byte in enumerate(data)
    )

    return restored.decode("utf-8")
