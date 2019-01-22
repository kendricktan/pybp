class RangeProof:
    def __init__(self, bitlength):
        self.fsstate = ''
        assert bitlength in [2, 4, 8, 16, 32, 64], "Bitlength must be power of 2 <= 64"
        self.bitlength = bitlength