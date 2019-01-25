import os
import hashlib
import binascii
import pybitcointools as B

from functools import reduce
from typing import List, Tuple

from pybp.utils import get_blinding_value, get_blinding_vector, getNUMS, modinv
from pybp.pederson import PedersonCommitment
from pybp.types import Scalar, Point
from pybp.vectors import Vector, to_bitvector, to_powervector
from pybp.innerproduct import InnerProductCommitment
from pybp.rangeproof import RangeProof
from typing import List, Union, Dict


def rp_fiat_shamir(fs_state, data: Union[List[Point], List[Scalar]], nret=2) -> List[Scalar]:
    """
    Generates nret integer chllange values from the currnet
    interaction (data) and the previous challenge values (fs_state),
    thus fulfilling the requirement of basing the challenge on the transcript of the
    prover-verifier communication up to this point
    """
    # Point type
    if isinstance(data[0], tuple):
        data_bs = reduce(lambda acc, x: acc +
                         B.encode_pubkey(x, 'hex_compressed'), data, "")
        xb: bytes = hashlib.sha256(
            fs_state + binascii.unhexlify(data_bs)).digest()

    # Scalar type
    elif isinstance(data[0], int):
        data_bs = reduce(lambda acc, x: acc +
                         str(x), data, "")
        xb: bytes = hashlib.sha256(fs_state + data_bs.encode('utf-8')).digest()

    else:
        raise Exception('Invalid `data` param type for fiat_shamir')

    challenges: List[Scalar] = []

    for i in range(nret):
        challenges.append(B.encode_privkey(xb, 'decimal'))
        xb = hashlib.sha256(xb).digest()

    return xb, challenges


def ipc_fiat_shamir(fs_state, L: Point, R: Point, P: Point) -> Tuple[Scalar, Scalar, Scalar, Scalar]:
    """
    Generates a challenge value x from the 'transcript' up to this point
    using the previous hash, and uses the L and R values from the current
    iteration, and commitment P. Returned is the value of the challenge
    and its modular inverse, as well as the squares of those values, both
    integers and binary strings, for convenience
    """
    data_bs: bytes = reduce(lambda acc, x: acc +
                            B.encode_pubkey(x, 'hex_compressed'), [L, R, P], b"")
    xb: bytes = hashlib.sha256(fs_state + data_bs).digest()

    x: Scalar = B.encode_privkey(xb, 'decimal') % B.N
    x_sq: Scalar = pow(x, 2, B.N)
    xinv: Scalar = modinv(x, B.N)
    x_sq_inv: Scalar = pow(xinv, 2, B.N)

    return xb, (x, x_sq, xinv, x_sq_inv)


proofval = 3
rangebits = 4

### Generate Proof ###


def generate_proof():
    global proofval, rangebits

    value = proofval
    bitlength = rangebits

    fsstate = b''

    zeros = Vector([0] * bitlength)
    ones = Vector([1] * bitlength)
    twos = Vector([2] * bitlength)
    power_of_twos = to_powervector(2, bitlength)

    gamma_bytes: bytes = b'\x9d\xe7\x80\xc2f=\x8f\xeaC~\xd6z\x81%\xe6k\xd6\xe5\x14e\xe7yA,%o\xae\x10\x0c0K\x97'
    gamma = B.encode_privkey(gamma_bytes, 'decimal')

    pc = PedersonCommitment(proofval, b=gamma)
    V = pc.get_commitment()

    aL = to_bitvector(value, bitlength)
    aR = aL - ones

    assert aL * aR == zeros
    assert aL @ power_of_twos == value

    alpha = 103151064230019145505666597105408187527020527690852467900472723045764939178262
    rho = 55973170476497972899146524197026400697030640964305412985865603418114122171929

    sL = Vector([20144717174267243584247126412021907276793462846970539360059288107735610647945, 15040251461887722561288264322239518061255819832348662582383129004704022603642,
                 97933652316292946183399427450438981090933603347955321067107393057352730507837, 395760878031994781938330167944309878346923484865345536819112065106106692942])
    sR = Vector([14124842355461766197909896783106869029133342296508845748032624852340316375340, 89639162977678097723449966442832874662389269036341555414004405789707095321607,
                 102334214897209200763475004672217056365567928242964950952587884298360981490106, 13247131849273667472247323801717593363591932098368978066674658505575722586872])

    ###

    A = InnerProductCommitment(aL, aR, c=alpha, U=getNUMS(255))
    P_a = A.get_commitment()

    S = InnerProductCommitment(sL, sR, c=rho, U=getNUMS(255))
    P_s = S.get_commitment()

    # print(B.encode_pubkey(P_s, 'hex_compressed'))
    fsstate, (y, z) = rp_fiat_shamir(fsstate, [V, P_a, P_s])

    z2 = (z * z) % B.N
    zv = Vector([z] * bitlength)

    # Construct l(x) and r(x) coefficients;
    # l[0] = constant term
    # l[1] = linear term
    # same for r(x)
    l: List[Vector] = [aL - zv, sL]
    yn: Vector = to_powervector(y, bitlength)

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

    tau1 = 52032351858479042087651896729883770634393744901975645088029089686116943575662
    tau2 = 27749385261680283883202504716235486084250497018876374255335247068460185881829

    T1 = PedersonCommitment(t1, b=tau1)
    T2 = PedersonCommitment(t2, b=tau2)

    fsstate, x_1 = rp_fiat_shamir(
        fsstate, [T1.get_commitment(), T2.get_commitment()], nret=1)
    x_1 = x_1[0]

    mu = (alpha + rho * x_1) % B.N
    tau_x = (tau1 * x_1 + tau2 * x_1 * x_1 + z2 * gamma) % B.N

    # lx and rx are vetor-value first degree polynomials evaluated at
    # the challenge value x_1
    lx = l[0] + (l[1] * x_1)
    rx = r[0] + (r[1] * x_1)
    t = (t0 + t1 * x_1 + t2 * x_1 * x_1) % B.N

    assert t == lx @ rx

    hprime = []
    yinv = modinv(y, B.N)

    for i in range(bitlength):
        hprime.append(
            B.multiply(A.H[i], pow(yinv, i, B.N))
        )

    fsstate, uchallenge = rp_fiat_shamir(fsstate, [tau_x, mu, t], nret=1)
    uchallenge = uchallenge[0]

    U = B.multiply(B.G, uchallenge)

    iproof = InnerProductCommitment(lx, rx, U=U, H=hprime)
    proof = iproof.generate_proof()

    ak: Scalar = proof[0]
    bk: Scalar = proof[1]
    lk: List[Point] = proof[2]
    rk: List[Point] = proof[3]

    iproof2 = InnerProductCommitment(ones, twos, H=hprime, U=U)

    assert iproof2.verify_proof(ak, bk, iproof.get_commitment(), lk, rk)

    return {
        'proof': proof,
        't': t,
        'mu': mu,
        'tau_x': tau_x,
        'Ap': A.get_commitment(),
        'Sp': S.get_commitment(),
        'T1p': T1.get_commitment(),
        'T2p': T2.get_commitment(),
        'V': V
    }


def verify_proof(proof_dict):
    global proofval, rangebits

    value = proofval
    bitlength = rangebits

    Ap = proof_dict['Ap']
    Sp = proof_dict['Sp']
    T1p = proof_dict['T1p']
    T2p = proof_dict['T2p']
    tau_x = proof_dict['tau_x']
    mu = proof_dict['mu']
    t = proof_dict['t']
    proof = proof_dict['proof']
    V = proof_dict['V']

    fsstate = b''

    fsstate, fs_challenge = rp_fiat_shamir(fsstate, [V, Ap, Sp])
    y = fs_challenge[0]
    z = fs_challenge[1]

    z: Scalar = fs_challenge[1]
    z2 = pow(z, 2, B.N)

    fsstate, x_1 = rp_fiat_shamir(fsstate, [T1p, T2p], nret=1)
    x_1 = x_1[0]

    # checked here

    # HPrime
    hprime = []
    yinv = modinv(y, B.N)

    for i in range(1, bitlength + 1):
        hprime.append(
            B.multiply(getNUMS(bitlength + i), pow(yinv, i-1, B.N))
        )

    # Construct verification equation (61)
    power_of_ones = to_powervector(1, bitlength)
    power_of_twos = to_powervector(2, bitlength)
    yn = to_powervector(y, bitlength)

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

    P = B.add_pubkeys(
        B.multiply(Sp, x_1),
        Ap
    )

    # Add g*^(-z)
    for i in range(bitlength):
        P = B.add_pubkeys(
            B.multiply(getNUMS(i+1), -z % B.N),
            P
        )

    zynz22n = (yn * z) + (power_of_twos * z2)

    for i in range(bitlength):
        P = B.add_pubkeys(
            B.multiply(hprime[i], zynz22n[i]),
            P
        )

    fsstate, uchallenge = rp_fiat_shamir(fsstate, [tau_x, mu, t], nret=1)
    uchallenge = uchallenge[0]

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
        power_of_ones,
        power_of_twos,
        H=hprime,
        U=U
    )

    print(iproof.verify_proof(a, b, p_prime, L, R))


if __name__ == '__main__':
    proof_dict = generate_proof()
    verify_proof(proof_dict)
