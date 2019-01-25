import hashlib
import binascii
import pybitcointools as B

from functools import reduce
from typing import List, Tuple, Union

from pybp.types import Point, Scalar
from pybp.vectors import Vector
from pybp.utils import getNUMS, split, modinv


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

    def __init__(self, a: Vector, b: Vector,
                 c: Union[None, Scalar] = None,
                 G: List[Point] = [],
                 H: List[Point] = [],
                 U: Union[None, Point] = None):
        assert len(a) == len(b)

        self.a = a
        self.b = b
        self.c: Scalar = c if c is not None else a @ b

        self.vlen = len(a)

        self.U = U if U is not None else getNUMS(0)
        self.G = G if len(G) > 0 else [getNUMS(i + 1)
                                       for i in range(self.vlen)]
        self.H = H if len(H) > 0 else [getNUMS(i + 1)
                                       for i in range(self.vlen, 2*self.vlen)]

        self.L = []
        self.R = []

    def get_commitment(self) -> Point:
        """
        Returns:

        c * U + v_1 * G_1 + v_2 * G_2 + ... + v_n * G_n +
        w_1 * H_1 + w_2 * H_2 + ... + w_n + H_n
        """
        P = B.multiply(self.U, self.c)

        for g_x, a_x in zip(self.G, self.a):
            P = B.add_pubkeys(P, B.fast_multiply(g_x, a_x))

        for h_x, b_x in zip(self.H, self.b):
            P = B.add_pubkeys(P, B.fast_multiply(h_x, b_x))

        return P

    def fiat_shamir(self, L: Point, R: Point, P: Point) -> Tuple[Scalar, Scalar, Scalar, Scalar]:
        """
        Generates a challenge value x from the 'transcript' up to this point
        using the previous hash, and uses the L and R values from the current
        iteration, and commitment P. Returned is the value of the challenge
        and its modular inverse, as well as the squares of those values, both
        integers and binary strings, for convenience
        """
        data_bs: bytes = reduce(lambda acc, x: acc +
                                B.encode_pubkey(x, 'hex_compressed'), [L, R, P], "")
        xb: bytes = hashlib.sha256(self.fs_state + binascii.unhexlify(data_bs)).digest()

        self.fs_state = xb

        x: Scalar = B.encode_privkey(xb, 'decimal') % B.N
        x_sq: Scalar = pow(x, 2, B.N)
        xinv: Scalar = modinv(x, B.N)
        x_sq_inv: Scalar = pow(xinv, 2, B.N)

        return (x, x_sq, xinv, x_sq_inv)

    def generate_proof(self) -> Tuple[Scalar, Scalar, List[Point], List[Point]]:
        self.fs_state = b''
        self.L = []
        self.R = []

        P = self.get_commitment()

        return self.get_proof_recursive(self.a, self.b, P,
                                        self.G, self.H, self.vlen)

    def get_proof_recursive(self,
                            a: Vector,
                            b: Vector,
                            P: Point,
                            G: List[Point],
                            H: List[Point],
                            N: int
                            ) -> Tuple[Scalar, Scalar, List[Point], List[Point]]:
        # Can't compress L and R no more
        if N == 1:
            # Return tuple a', b', L[], R[]
            # total size is 2 * scalar_size * log(n) * 2 * point_size
            return (a[0], b[0], self.L, self.R)

        aL, aR = split(a)
        bL, bR = split(b)
        gL, gR = split(G)
        hL, hR = split(H)

        self.L.append(
            InnerProductCommitment(
                aL, bR, G=gR, H=hL, U=self.U).get_commitment()
        )
        self.R.append(
            InnerProductCommitment(
                aR, bL, G=gL, H=hR, U=self.U).get_commitment()
        )

        (x, x_sq, xinv, x_sq_inv) = self.fiat_shamir(self.L[-1], self.R[-1], P)

        # Construct change of coordinates for base points, and for vector terms
        gprime = []
        hprime = []
        aprime = []
        bprime = []

        for i in range(int(N / 2)):
            gprime.append(
                B.add_pubkeys(
                    B.multiply(G[i], xinv),
                    B.multiply(G[i + int(N / 2)], x)
                )
            )

            hprime.append(
                B.add_pubkeys(
                    B.multiply(H[i], x),
                    B.multiply(H[i + int(N / 2)], xinv)
                )
            )

            aprime.append(
                x * a[i] + xinv * a[i + int(N / 2)] % B.N
            )

            bprime.append(
                (xinv * b[i]) + x * b[i + int(N / 2)] % B.N
            )

        p_prime1 = B.add_pubkeys(P, B.multiply(self.L[-1], x_sq))
        p_prime = B.add(p_prime1, B.multiply(self.R[-1], x_sq_inv))

        return self.get_proof_recursive(
            Vector(aprime),
            Vector(bprime),
            p_prime,
            gprime,
            hprime,
            int(N / 2)
        )

    def verify_proof(self, a: Vector, b: Vector, P: Point, L: List[Point], R: List[Point]):
        """
        Given proof (a, b, L, R) and the original pedersen commitment P,
        validates the proof that the commitment is to vectors a*, b* whose
        inner product is committed to (i.e. validates it is of form
            P = a*G + b*G + <a,b>U
        )
        Note that this call will ignore the vectors a* and b* set in
        the construct, so they can be dummy values as long as the length
        is correct

        returns: Bool
        """
        self.verify_iter = 0
        self.fs_state = b''

        return self.verify_proof_recursive(P, L, R, a, b, self.G, self.H, self.vlen)

    def verify_proof_recursive(self,
                               P: Point,
                               L: Point,
                               R: Point,
                               a: Scalar,
                               b: Scalar,
                               G: List[Point],
                               H: List[Point],
                               N: int):
        if N == 1:
            p_prime = InnerProductCommitment(
                Vector([a]), Vector([b]), G=G, H=H, U=self.U).get_commitment()

            return P == p_prime

        (x, x_sq, xinv, x_sq_inv) = self.fiat_shamir(
            L[self.verify_iter], R[self.verify_iter], P)

        gprime = []
        hprime = []

        for i in range((int(N / 2))):
            gprime.append(
                B.add_pubkeys(
                    B.multiply(G[i], xinv),
                    B.multiply(G[i + int(N / 2)], x)
                )
            )

            hprime.append(
                B.add_pubkeys(
                    B.multiply(H[i], x),
                    B.multiply(H[i + int(N / 2)], xinv)
                )
            )
        
        p_prime1 = B.add_pubkeys(
            P, B.multiply(L[self.verify_iter], x_sq)
        )
        p_prime = B.add_pubkeys(
            p_prime1, B.multiply(R[self.verify_iter], x_sq_inv)
        )

        self.verify_iter = self.verify_iter + 1

        return self.verify_proof_recursive(
            p_prime,
            L,
            R,
            a,
            b,
            gprime,
            hprime,
            int(N / 2)
        )