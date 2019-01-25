import os
import pybp

import pybitcointools as B

from typing import Union
from pybp.utils import get_blinding_value
from pybp.types import Scalar, Point

class PedersonCommitment:
    def __init__(self, v: Scalar, b=Union[None, Scalar]):
        self.g: Point  = B.getG()
        self.h: Point = pybp.utils.getNUMS(255)

        # Value to hide
        self.v: Scalar = v

        # Blinding Factor
        self.b: Scalar = b if isinstance(b, int) else get_blinding_value()

    def get_commitment(self) -> Point:
        Hb = B.multiply(self.h, self.b)
        Gv = B.multiply(self.g, self.v)        

        return B.add(Hb, Gv)
