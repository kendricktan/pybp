import pybitcointools as B

from pybp.types import Point, Scalar
from pybp.vectors import Vector
from pybp.utils import getNUMS


class InnerProductCommitment:
    """
    P = a*G + b*H + <a, b>U
    Where * indicates a vector, and <,> an inner product

    The two vectors under proof are a* and b*. G*, H* and U
    are all NUMS basepoints.

    The commitment has a structure:
    P = c*U + a_1*G_1 +a_2*G_2 + ... + a_n *G_n +
    b_1*H_1 + b_2*H_2 + ... b_n*H_n

    Where:
    c is the 'blinding amount' or the inner product
    a, b are vectors of integer values in Z_n
    U, is NUMS based points
    G, H are a list of NUMS based points
    P is the single-EC point commitment created
    """

    def __init__(self, a: Vector, b: Vector):
        assert len(a) == len(b)

        self.a = a
        self.b = b
        self.c: Scalar = a @ b

        self.vlen = len(a)

        self.U = getNUMS(0)
        self.G = [getNUMS(i + 1) for i in range(self.vlen)]
        self.H = [getNUMS(i + 1) for i in range(self.vlen, 2*self.vlen)]

        self.L = []
        self.R = []

    def get_commitment(self) -> Point:
        """
        Returns:

        c * U + v_1 * G_1 + v_2 * G_2 + ... + v_n * G_n +
        w_1 * H_1 + w_2 * H_2 + ... + w_n + H_n
        """
        P = B.fast_multiply(self.U, self.c)

        for g_x, a_x in zip(self.G, self.a):
            P = B.add_pubkeys(P, B.fast_multiply(g_x, a_x))

        for h_x, b_x in zip(self.H, self.b):
            P = B.add_pubkeys(P, B.fast_multiply(h_x, b_x))

        return P
