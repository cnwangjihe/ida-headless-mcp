"""Tests for composite analysis helpers."""

from ..api_composite import _filter_constants
from ..framework import test


@test()
def test_filter_constants_uses_extractor_decimal_values():
    """Hex display strings do not hide non-trivial immediate values."""
    raw = [
        {"addr": "0x10", "value": "0x200", "decimal": 0x200},
        {"addr": "0x20", "value": "0x1", "decimal": 1},
        {"addr": "0x30", "value": 0x400},
        {"addr": "0x40", "value": "invalid"},
    ]

    result = _filter_constants(raw)

    assert [item["addr"] for item in result] == ["0x30", "0x10"]
