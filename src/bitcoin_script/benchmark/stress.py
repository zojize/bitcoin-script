"""Era definitions, stress block identification, and block selection logic."""

from __future__ import annotations

_PRE_P2SH_END = 173_804
_P2SH_START = 173_805
_DERSIG_START = 363_725
_CLTV_START = 388_381
_CSV_START = 419_328
_SEGWIT_START = 481_824
_TAPROOT_START = 709_632

ERA_RANGES: dict[str, tuple[int, int]] = {
    "pre-p2sh": (0, _PRE_P2SH_END),
    "p2sh": (_P2SH_START, _DERSIG_START - 1),
    "dersig": (_DERSIG_START, _CLTV_START - 1),
    "cltv": (_CLTV_START, _CSV_START - 1),
    "csv": (_CSV_START, _SEGWIT_START - 1),
    "segwit": (_SEGWIT_START, _TAPROOT_START - 1),
    "taproot": (_TAPROOT_START, 900_000),
}

_ERA_THRESHOLDS: list[tuple[int, str]] = [
    (_TAPROOT_START, "taproot"),
    (_SEGWIT_START, "segwit"),
    (_CSV_START, "csv"),
    (_CLTV_START, "cltv"),
    (_DERSIG_START, "dersig"),
    (_P2SH_START, "p2sh"),
    (0, "pre-p2sh"),
]


def classify_era(height: int) -> str:
    """Return the consensus era name for a given block height."""
    for threshold, era in _ERA_THRESHOLDS:
        if height >= threshold:
            return era
    return "pre-p2sh"


def select_representative_heights(
    blocks_per_era: int = 10,
    *,
    skip_taproot: bool = False,
) -> list[int]:
    """Select evenly-spaced block heights from each consensus era."""
    heights: list[int] = []
    for era, (lo, hi) in ERA_RANGES.items():
        if skip_taproot and era == "taproot":
            continue
        span = hi - lo
        if span < blocks_per_era:
            heights.extend(range(lo, hi + 1))
        else:
            step = span // blocks_per_era
            for i in range(blocks_per_era):
                heights.append(lo + i * step)
    return sorted(heights)


KNOWN_STRESS_BLOCKS: list[int] = [
    364_422,
    367_891,
    364_292,
    371_623,
    400_002,
    481_829,
    481_947,
    482_897,
]
