"""Tests against known real Bitcoin mainnet transactions."""


class TestMainnetTransactions:
    def test_block_170_first_transaction(self) -> None:
        """First non-coinbase transaction ever: Satoshi -> Hal Finney.

        Block 170, tx f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
        This is a P2PK (not P2PKH) transaction.
        """
        ...

    def test_first_p2pkh_transaction(self) -> None:
        """First P2PKH transaction on mainnet."""
        ...

    def test_first_p2sh_transaction(self) -> None:
        """First P2SH transaction after BIP16 activation."""
        ...

    def test_first_segwit_transaction(self) -> None:
        """First SegWit transaction after activation."""
        ...
