
import ast


def split_string(text: str, chunk_size: int = 3) -> list[str]:
    """Divide text into smaller pieces."""
    if chunk_size < 1:
        raise ValueError("Chunk size must be at least 1.")

    return [
        text[i:i + chunk_size]
        for i in range(0, len(text), chunk_size)
    ]


def reconstruct_string(parts: list[str]) -> str:
    """Join string pieces back into the original text."""
    return "".join(parts)


def escape_representation(text: str) -> str:
    """Return a readable escaped representation of text."""
    return ascii(text)


def restore_escape_representation(escaped: str) -> str:
    """Restore text from a valid Python string representation."""
    try:
        result = ast.literal_eval(escaped)
    except (ValueError, SyntaxError) as exc:
        raise ValueError("Invalid escaped string representation.") from exc

    if not isinstance(result, str):
        raise ValueError("The representation must describe a string.")

    return result
