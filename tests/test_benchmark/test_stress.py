"""Tests for era classification, stress block list, and block selection."""

from __future__ import annotations

from bitcoin_script.benchmark.stress import (
    ERA_RANGES,
    KNOWN_STRESS_BLOCKS,
    classify_era,
    select_representative_heights,
)


class TestClassifyEra:
    def test_genesis_is_pre_p2sh(self) -> None:
        assert classify_era(0) == "pre-p2sh"

    def test_p2sh_era(self) -> None:
        assert classify_era(173_805) == "p2sh"

    def test_dersig_era(self) -> None:
        assert classify_era(363_725) == "dersig"

    def test_cltv_era(self) -> None:
        assert classify_era(388_381) == "cltv"

    def test_csv_era(self) -> None:
        assert classify_era(419_328) == "csv"

    def test_segwit_era(self) -> None:
        assert classify_era(481_824) == "segwit"

    def test_taproot_era(self) -> None:
        assert classify_era(709_632) == "taproot"

    def test_boundary_pre_p2sh(self) -> None:
        assert classify_era(173_804) == "pre-p2sh"

    def test_boundary_before_segwit(self) -> None:
        assert classify_era(481_823) == "csv"


class TestSelectRepresentativeHeights:
    def test_returns_correct_count_per_era(self) -> None:
        heights = select_representative_heights(blocks_per_era=5)
        eras = {classify_era(h) for h in heights}
        assert "pre-p2sh" in eras
        assert "segwit" in eras

    def test_heights_within_era_ranges(self) -> None:
        heights = select_representative_heights(blocks_per_era=3)
        for h in heights:
            era = classify_era(h)
            lo, hi = ERA_RANGES[era]
            assert lo <= h <= hi, f"height {h} not in {era} range [{lo}, {hi}]"

    def test_heights_evenly_spaced(self) -> None:
        heights = select_representative_heights(blocks_per_era=10)
        by_era: dict[str, list[int]] = {}
        for h in heights:
            by_era.setdefault(classify_era(h), []).append(h)
        for era, hs in by_era.items():
            assert hs == sorted(set(hs)), f"{era} heights not sorted/unique"


class TestKnownStressBlocks:
    def test_stress_blocks_not_empty(self) -> None:
        assert len(KNOWN_STRESS_BLOCKS) > 0

    def test_stress_blocks_are_positive(self) -> None:
        assert all(h > 0 for h in KNOWN_STRESS_BLOCKS)
