"""Tests for the flag activation schedule."""

from __future__ import annotations

from bitcoin_script.blockchain.flags import (
    CHECKLOCKTIMEVERIFY,
    CHECKSEQUENCEVERIFY,
    CLEANSTACK,
    DERSIG,
    LOW_S,
    MINIMALDATA,
    MINIMALIF,
    NULLDUMMY,
    NULLFAIL,
    P2SH,
    SIGPUSHONLY,
    STRICTENC,
    WITNESS,
    WITNESS_PUBKEYTYPE,
    flags_for_block,
)


class TestFlagSchedule:
    def test_genesis_no_flags(self) -> None:
        """Genesis block (height 0, timestamp ~2009) has no flags."""
        assert flags_for_block(0, 1231006505) == 0

    def test_p2sh_activation(self) -> None:
        """P2SH activates at timestamp 1333238400."""
        assert flags_for_block(0, 1333238399) == 0
        assert flags_for_block(0, 1333238400) & P2SH == P2SH

    def test_dersig_activation(self) -> None:
        """DERSIG activates at height 363725."""
        f_before = flags_for_block(363724, 1500000000)
        f_after = flags_for_block(363725, 1500000000)
        assert f_before & DERSIG == 0
        assert f_after & DERSIG == DERSIG

    def test_cltv_activation(self) -> None:
        """CLTV activates at height 388381."""
        assert flags_for_block(388380, 1500000000) & CHECKLOCKTIMEVERIFY == 0
        assert flags_for_block(388381, 1500000000) & CHECKLOCKTIMEVERIFY != 0

    def test_csv_activation(self) -> None:
        """CSV activates at height 419328."""
        assert flags_for_block(419327, 1500000000) & CHECKSEQUENCEVERIFY == 0
        assert flags_for_block(419328, 1500000000) & CHECKSEQUENCEVERIFY != 0

    def test_segwit_activation(self) -> None:
        """SegWit activates at height 481824 with many flags."""
        f = flags_for_block(481824, 1500000000)
        for flag in [
            WITNESS,
            NULLDUMMY,
            STRICTENC,
            LOW_S,
            NULLFAIL,
            SIGPUSHONLY,
            MINIMALDATA,
            CLEANSTACK,
            MINIMALIF,
            WITNESS_PUBKEYTYPE,
        ]:
            assert f & flag == flag, f"flag {flag} not set at SegWit activation"

    def test_pre_segwit_no_witness(self) -> None:
        """Before SegWit, WITNESS flag should not be set."""
        assert flags_for_block(481823, 1500000000) & WITNESS == 0
