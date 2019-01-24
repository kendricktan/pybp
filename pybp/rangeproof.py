import os
import hashlib

import pybitcointools as B

from functools import reduce
from typing import List

from pybp.utils import get_blinding_value, get_blinding_vector, getNUMS
from pybp.pederson import PedersonCommitment
from pybp.types import Scalar, Point
from pybp.vectors import Vector, to_bitvector, to_powervector
from pybp.innerproduct import InnerProductCommitment


class RangeProof:
    """
    Based on Bulletproof paper: https://eprint.iacr.org/2017/1066.pdf
    """

    def __init__(self, bitlength):
        assert bitlength in [2, 4, 8, 16, 32,
                             64], "Bitlength must be power of 2 <= 64"
        self.bitlength = bitlength

    def fiat_shamir(self, data: List[Point], nret=2) -> List[Scalar]:
        """
        Generates nret integer chllange values from the currnet
        interaction (data) and the previous challenge values (self.fs_state),
        thus fulfilling the requirement of basing the challenge on the transcript of the
        prover-verifier communication up to this point
        """
        data_bs: bytes = reduce(lambda acc, x: acc +
                                B.encode_pubkey(x, 'bin_compressed'), data, b"")
        xb: bytes = hashlib.sha256(self.fs_state + data_bs).digest()

        challenges: List[Scalar] = []

        for i in range(nret):
            challenges.append(B.decode_privkey(xb, 'bin'))
            xb = hashlib.sha256(xb).digest()

        self.fs_state = xb
        return challenges

    def generate_proof(self, value: Scalar):
        """
        Given a value, follow the algorithm laid out
        on p.16, 17 (section 4.2) of paper for prover side
        """
        self.fs_state = b''

        # Vector of all 1's or 0's
        # Mainly for readability
        zeros = Vector([0] * self.bitlength)
        ones = Vector([1] * self.bitlength)
        power_of_twos = to_powervector(2, self.bitlength)

        aL = to_bitvector(value, self.bitlength)
        aR = aL - ones

        assert aL * aR == zeros
        assert aL @ power_of_twos == value

        # Pederson Commitment to fulfill the hiding and binding properties
        # of bulletproof. Binding value is automatically created
        gamma = get_blinding_value()
        pc = PedersonCommitment(value)
        pc.b = gamma
        V: Point = pc.get_commitment()

        alpha: Scalar = get_blinding_value()
        rho = get_blinding_value()

        A = InnerProductCommitment(aL, aR)
        A.U = getNUMS(255)
        A.c = alpha
        P_a: Point = A.get_commitment()

        sL = get_blinding_vector(self.bitlength)
        sR = get_blinding_vector(self.bitlength)

        S = InnerProductCommitment(sL, sR)
        S.U = getNUMS(255)
        S.c = rho
        P_s: Point = S.get_commitment()

        fs_challanges = self.fiat_shamir([V, P_a, P_s])
        y: Point = fs_challanges[0]
        z: Point = fs_challanges[1]

        z2 = (z * z) % B.N
        zv = Vector([z] * self.bitlength)

        # Construct l(x) and r(x) coefficients;
        # l[0] = constant term
        # l[1] = linear term
        # same for r(x)
        l: List[Vector] = [aL - zv, sL]
        yn: Vector = to_powervector(y, self.bitlength)

        # 0th coeff is y^n ⋅ (aR + z . 1^n) + z^2 . 2^n
        # operators have been overloaded, so all good
        r: List[Vector] = [
            (yn * (aR + zv)) + (power_of_twos * z2), # operator overloading works if vector is first
            yn * sR
        ]

        # Constant term of t(x) = <l(x), r(x)> is the inner product
        # of the constant terms of l(x)and r(x)
        t0 = l[0] @ r[0]
        t1 = ((l[0] @ r[1]) + (l[1] @ r[0])) % B.N
        t2 = l[1] @ r[1]

        T1 = PedersonCommitment(t1)
        tau1 = T1.b # T1.b is the blinding factor
        
        T2 = PedersonCommitment(t2)
        tau2 = T2.b

        x_1: Scalar = self.fiat_shamir([T1.get_commitment(), T2.get_commitment()], nret=1)[0]
        mu = (alpha + rho * x_1) % B.N
        tau_x = (tau1 * x_1 + tau2 * x_1 * x_1 + z2 * gamma) % B.N

        # lx and rx are vetor-value first degree polynomials evaluated at
        # the challenge value x_1
        lx = l[0] + (l[1] * x_1)
        rx = r[0] + (r[1] * x_1)
        t = (t0 + t1 * x_1 + t2 * x_1 * x_1) % B.N

        assert t == lx @ rx