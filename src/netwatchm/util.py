"""Small shared formatting helpers."""
from __future__ import annotations


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
