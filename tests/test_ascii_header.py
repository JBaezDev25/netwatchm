"""Tests for ascii_header — keeps ntfy HTTP header values latin-1 safe."""
from __future__ import annotations

from netwatchm.util import ascii_header


def test_em_dash_replaced():
    # The exact char that broke the digest push (U+2014).
    out = ascii_header("NetWatchM — daily digest")
    assert out == "NetWatchM - daily digest"
    out.encode("latin-1")  # must not raise


def test_arrow_and_quotes():
    assert ascii_header("10.0.0.9 → 224.0.0.1") == "10.0.0.9 -> 224.0.0.1"
    assert ascii_header("“quoted” ‘x’") == '"quoted" \'x\''
    assert ascii_header("a…") == "a..."


def test_unmapped_non_ascii_dropped():
    out = ascii_header("emoji \U0001f916 test é")
    out.encode("latin-1")  # must not raise
    assert "test" in out
    assert "\U0001f916" not in out


def test_plain_ascii_unchanged():
    assert ascii_header("[HIGH] Port scan detected") == "[HIGH] Port scan detected"
