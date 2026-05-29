"""Small shared formatting helpers."""
from __future__ import annotations

# Common typographic characters mapped to ASCII so they survive an HTTP header
# value. http.client encodes header values as latin-1, so non-latin-1 chars
# (em-dash, arrows, curly quotes) otherwise raise a UnicodeEncodeError.
_HEADER_TRANSLATIONS = {
    "—": "-",    # em dash —
    "–": "-",    # en dash –
    "‘": "'",    # left single quote ‘
    "’": "'",    # right single quote ’
    "“": '"',    # left double quote “
    "”": '"',    # right double quote ”
    "…": "...",  # ellipsis …
    "→": "->",   # right arrow → (used in beacon/agent descriptions)
    "·": "-",    # middle dot ·
}


def ascii_header(value: str) -> str:
    """Return a string safe to use as an HTTP header value.

    Replaces common typographic characters with ASCII equivalents, then drops
    any remaining non-ASCII characters. Used for ntfy ``X-Title``/``X-Tags``
    headers, which must be latin-1/ASCII encodable.
    """
    for bad, good in _HEADER_TRANSLATIONS.items():
        value = value.replace(bad, good)
    return value.encode("ascii", "ignore").decode("ascii")


def format_bytes(
    n: float,
    *,
    precision: int = 1,
    units: tuple[str, ...] = ("B", "KB", "MB", "GB"),
    overflow: str = "TB",
    float_div: bool = False,
) -> str:
    """Render a byte count as a human-readable string.

    ``precision`` decimal places; ``units`` are the ladder rungs and
    ``overflow`` the label used once the count exceeds the last rung.
    ``float_div`` keeps fractional remainders (e.g. ``1.5 KB``) instead of
    flooring each step (``1.0 KB``).
    """
    for unit in units:
        if n < 1024:
            return f"{n:.{precision}f} {unit}"
        n = n / 1024 if float_div else n // 1024
    return f"{n:.{precision}f} {overflow}"
