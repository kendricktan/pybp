import os
import hashlib

import pybitcointools as B

from functools import reduce
from typing import List, Union, Dict

from pybp.utils import get_blinding_value, get_blinding_vector, getNUMS, modinv
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

    def fiat_shamir(self, data: Union[List[Point], List[Scalar]], nret=2) -> List[Scalar]:
        """
        Generates nret integer chllange values from the currnet
        interaction (data) and the previous challenge values (self.fs_state),
        thus fulfilling the requirement of basing the challenge on the transcript of the
        prover-verifier communication up to this point
        """
        # Point type
        if isinstance(data[0], tuple):
            data_bs: bytes = reduce(lambda acc, x: acc +
                                    B.encode_pubkey(x, 'bin'), data, b"")

        # Scalar type
        elif isinstance(data[0], int):
            data_bs: bytes = reduce(lambda acc, x: acc +
                                    B.encode_privkey(x, 'bin'), data, b"")

        else:
            raise Exception('Invalid `data` param type for fiat_shamir')
        xb: bytes = hashlib.sha256(self.fs_state + data_bs).digest()

        challenges: List[Scalar] = []

        for i in range(nret):
            challenges.append(B.encode_privkey(xb, 'decimal'))
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
        twos = Vector([2] * self.bitlength)
        power_of_twos = to_powervector(2, self.bitlength)

        aL = to_bitvector(value, self.bitlength)
        aR = aL - ones

        assert aL * aR == zeros
        assert aL @ power_of_twos == value

        # Pederson Commitment to fulfill the hiding and binding properties
        # of bulletproof. Binding value is automatically created
        gamma = get_blinding_value()
        pc = PedersonCommitment(value, b=gamma)
        V: Point = pc.get_commitment()

        alpha: Scalar = get_blinding_value()
        rho = get_blinding_value()

        A = InnerProductCommitment(aL, aR, c=alpha, U=getNUMS(255))
        P_a: Point = A.get_commitment()

        sL = get_blinding_vector(self.bitlength)
        sR = get_blinding_vector(self.bitlength)

        S = InnerProductCommitment(sL, sR, c=rho, U=getNUMS(255))
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
            # operator overloading works if vector is first
            (yn * (aR + zv)) + (power_of_twos * z2),
            yn * sR
        ]

        # Constant term of t(x) = <l(x), r(x)> is the inner product
        # of the constant terms of l(x)and r(x)
        t0 = l[0] @ r[0]
        t1 = ((l[0] @ r[1]) + (l[1] @ r[0])) % B.N
        t2 = l[1] @ r[1]

        T1 = PedersonCommitment(t1)
        tau1 = T1.b  # T1.b is the blinding factor

        T2 = PedersonCommitment(t2)
        tau2 = T2.b

        x_1: Scalar = self.fiat_shamir(
            [T1.get_commitment(), T2.get_commitment()], nret=1)[0]
        mu = (alpha + rho * x_1) % B.N
        tau_x = (tau1 * x_1 + tau2 * x_1 * x_1 + z2 * gamma) % B.N

        # lx and rx are vetor-value first degree polynomials evaluated at
        # the challenge value x_1
        lx = l[0] + (l[1] * x_1)
        rx = r[0] + (r[1] * x_1)
        t = (t0 + t1 * x_1 + t2 * x_1 * x_1) % B.N

        assert t == lx @ rx

        # Prover can new send tau_x, mu and t to verifier
        # inner product argument can be verified from this data
        hprime = []
        yinv = modinv(y, B.N)

        for i in range(self.bitlength):
            hprime.append(
                B.multiply(A.H[i], pow(yinv, i, B.N))
            )

        uchallenge = self.fiat_shamir([tau_x, mu, t], nret=1)[0]
        U = B.multiply(B.G, uchallenge)

        # On the prover side, need to construct an inner product argument
        iproof = InnerProductCommitment(lx, rx, U=U, H=hprime)
        proof = iproof.generate_proof()

        ak: Scalar = proof[0]
        bk: Scalar = proof[1]
        lk: List[Point] = proof[2]
        rk: List[Point] = proof[3]

        # At this point we have a valid data set, but here is included a
        # sanity check that the inner product proof we've generated actually verifies
        iproof2 = InnerProductCommitment(ones, twos, H=hprime, U=U)
        
        assert iproof2.verify_proof(ak, bk, iproof.get_commitment(), lk, rk)
        
        self.proof = proof
        self.tau_x = tau_x
        self.gamma = gamma
        self.mu = mu
        self.T1 = T1
        self.T2 = T2
        self.A = A
        self.S = S
        self.t = t
        self.V = V
        

    def get_proof_dict(self) -> Dict:
        """
        Returns the rangeproof that's been created in dictionary format.
        And all scalars are fixed length 32 bytes, including the (a, b)
        components of the inner pdocut proof. The exception is L, R which are
        arrays of EC points, length log_2(bitlength).

        So total size of proof is 33*4 + 32*3 + (32*2 + 33*2*log_2(bitlength)).
        This agrees with the last sentence of 4.2 in the paper
        """

        return {
            'proof': self.proof,
            't': self.t,
            'mu': self.mu,
            'tau_x': self.tau_x,
            'Ap': self.A.get_commitment(),
            'Sp': self.S.get_commitment(),
            'T1p': self.T1.get_commitment(),
            'T2p': self.T2.get_commitment()
        }

    def verify(self, Ap, Sp, T1p, T2p, tau_x, mu, t, proof, V):
        self.fs_state = b''

        # Compute challenges to find x, y, z
        fs_challenge = self.fiat_shamir([V, Ap, Sp])
        y: Scalar = fs_challenge[0]
        z: Scalar = fs_challenge[1]
        z2 = pow(z, 2, B.N)

        x_1 = self.fiat_shamir([T1p, T2p], nret=1)[0]

        # Construct verification equation (61)
        power_of_ones = to_powervector(1, self.bitlength)
        power_of_twos = to_powervector(2, self.bitlength)
        yn = to_powervector(y, self.bitlength)

        k: Scalar = ((yn @ power_of_ones) * (-z2)) % B.N
        k = (k - (power_of_ones @ power_of_twos) * pow(z, 3, B.N)) % B.N

        gexp: Scalar = (k + z * (power_of_ones @ yn)) % B.N

        lhs = PedersonCommitment(t, b=tau_x).get_commitment()

        rhs = B.multiply(B.G, gexp)
        rhs = B.add_pubkeys(rhs, B.multiply(V, z2))
        rhs = B.add_pubkeys(rhs, B.multiply(T1p, x_1))
        rhs = B.add_pubkeys(rhs, B.multiply(T2p, pow(x_1, 2, B.N)))

        if not lhs == rhs:
            raise Exception('(61) verification check failed')

        # HPrime
        hprime = []
        yinv = modinv(y, B.N)

        for i in range(1, self.bitlength + 1):
            hprime.append(
                B.multiply(getNUMS(self.bitlength + i), pow(yinv, i-1, B.N))
            )

        # Reconstruct P
        P = B.add_pubkeys(
            B.multiply(Sp, x_1),
            Ap
        )

        # Add g*^(-z)
        for i in range(self.bitlength):
            P = B.add_pubkeys(
                B.multiply(getNUMS(i+1), -z % B.N),
                P
            )

        # zynz22n is the exponent of hprime
        zynz22n = (yn * z) + (power_of_twos * z2)

        for i in range(self.bitlength):
            P = B.add_pubkeys(
                B.multiply(hprime[i], zynz22n[i]),
                P
            )

        uchallenge = self.fiat_shamir([tau_x, mu, t], nret=1)[0]
        U = B.multiply(B.G, uchallenge)
        P = B.add_pubkeys(
            B.multiply(U, t),
            P
        )

        # P should now be : A + xS + -zG* + (zy^n+z^2.2^n)H'* + tU
        # One can show algebraically (the working is omitted from the paper)
        # that this will be the same as an inner product commitment to
        # (lx, rx) vectors (whose inner product is t), thus the variable 'proof'
        # can be passed into the IPC verify call, which should pass.
        # input to inner product proof is P.h^-(mu)
        p_prime = B.add_pubkeys(
            P,
            B.multiply(getNUMS(255), -mu % B.N)
        )

        a, b, L, R = proof

        iproof = InnerProductCommitment(
            Vector([1] * self.bitlength),
            Vector([2] * self.bitlength),
            H=hprime,
            U=U
        )

        return iproof.verify_proof(a, b, p_prime, L, R)