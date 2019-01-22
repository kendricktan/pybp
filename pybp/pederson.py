import os
import pybp

import pybitcointools as B

from pybp.types import Scalar, Point

class PedersonCommitment:
    def __init__(self, v: Scalar):
        self.g: Point  = B.getG()
        self.h: Point = pybp.utils.getNUMS(255)

        # Value to hide
        self.v: Scalar = v

        # Blinding Factor
        self.b: Scalar = B.encode_privkey(os.urandom(32), 'decimal')

    def get_commitment(self) -> Point:
        Hb = B.multiply(self.h, self.b)
        Gv = B.multiply(self.g, self.v)

        return B.add(Hb, Gv)


class VectorPedersonCommitment:
    def __init__(self):
        pass