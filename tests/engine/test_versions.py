"""Version comparison regressions (review E6, E14, E15)."""

from __future__ import annotations

import pytest

from secmonk.engine.versions import compare, in_osv_range, is_parseable

G = "generic"


@pytest.mark.parametrize("a,b,expected", [
    ("1.1.1w", "1.1.1", 1),          # OpenSSL letter releases are post-releases
    ("1.1.1w", "1.1.1t", 1),
    ("1.1.1a", "1.1.1", 1),
    ("9.8p1", "9.8", 1),             # OpenSSH portable
    ("9.8p1", "9.9", -1),
    ("1.0pl2", "1.0", 1),
    ("1.0-patch1", "1.0", 1),
    ("1.2.3.Final", "1.2.3", 0),
    ("1.2.3.GA", "1.2.3.0", 0),
    ("1.0-rc1", "1.0", -1),
    ("1.0.0-rc1", "1.0-rc1", 0),
    ("1.0-rc1", "1.0-rc2", -1),
    ("1.0-alpha", "1.0-beta", -1),
    ("1.0-b2", "1.0", -1),           # 'b' after '-' is beta
    ("1.0-dev", "1.0-alpha", -1),
    ("1.0-preview1", "1.0-rc1", -1),
    ("1.0-rc1", "0.9", 1),
    ("1.0", "1.0.0", 0),
    ("1.2.3_1", "1.2.3", 1),         # Homebrew revision
    ("v2.1", "2.1.0", 0),
    ("2.4.58", "2.4.6", 1),
])
def test_generic_suffix_ordering(a, b, expected):
    assert compare(a, b, G) == expected
    assert compare(b, a, G) == -expected


def test_generic_ranges_with_suffixes():
    assert in_osv_range("1.1.1t", [{"introduced": "1.1.1"}, {"fixed": "1.1.1w"}], G)
    assert in_osv_range("1.1.1", [{"introduced": "0"}, {"fixed": "1.1.1a"}], G)
    assert not in_osv_range("9.8p1", [{"introduced": "8.5"}, {"fixed": "9.8"}], G)
    assert in_osv_range("1.0-rc1", [{"introduced": "0"}, {"fixed": "1.0"}], G)


@pytest.mark.parametrize("events,version,expected", [
    ([{"fixed": "1.2"}, {"introduced": "0"}], "5.0", False),
    ([{"fixed": "1.2"}, {"introduced": "0"}], "1.0", True),
    ([{"introduced": "1.0"}, {"introduced": "1.5"}, {"fixed": "2.0"}], "1.2", True),   # 2nd introduced: no-op
    ([{"introduced": "2.0"}, {"fixed": "2.1"}, {"introduced": "0"}, {"fixed": "1.2"}], "1.0", True),
    ([{"introduced": "2.0"}, {"fixed": "2.1"}, {"introduced": "0"}, {"fixed": "1.2"}], "1.5", False),
    ([{"introduced": "2.0"}, {"fixed": "2.1"}, {"introduced": "0"}, {"fixed": "1.2"}], "2.0.5", True),
    ([{"last_affected": "1.4"}, {"introduced": "1.0"}], "1.4", True),
    ([{"last_affected": "1.4"}, {"introduced": "1.0"}], "1.4.1", False),
    ([{"introduced": "1.0"}, {"fixed": "1.0"}], "1.0", False),          # empty interval
    ([{"introduced": "0"}, {"limit": "2.0"}], "2.0", False),
    ([{"introduced": "0"}, {"limit": "2.0"}], "1.9", True),
])
def test_osv_range_is_order_independent(events, version, expected):
    assert in_osv_range(version, events, "eco:PyPI") is expected
    assert in_osv_range(version, list(reversed(events)), "eco:PyPI") is expected


@pytest.mark.parametrize("v,expected", [
    ("1.2.3", True), ("v2", True), (" 10.0.22631", True),
    ("build 2024 (beta) ???", False), ("Version ??? (beta)", False), ("", False), ("beta", False),
])
def test_generic_parseable_requires_leading_digit(v, expected):
    assert is_parseable(v, G) is expected
