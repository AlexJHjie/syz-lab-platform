from __future__ import annotations


def parse_duration(value: str | int | float | None) -> int | None:
    """Parse a duration string into seconds.

    Accepted examples: 600, "600", "10m", "2h", "1d".
    """

    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)

    raw = str(value).strip().lower()
    if not raw:
        return None

    unit = raw[-1]
    if unit.isdigit():
        return int(raw)

    number = int(raw[:-1])
    multipliers = {
        "s": 1,
        "m": 60,
        "h": 60 * 60,
        "d": 24 * 60 * 60,
    }
    if unit not in multipliers:
        raise ValueError(f"unsupported duration suffix: {value}")
    return number * multipliers[unit]
