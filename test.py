import os
import hashlib

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
    xb: bytes = hashlib.sha256(fs_state + data_bs).digest()

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
                            B.encode_pubkey(x, 'bin'), [L, R, P], b"")
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

    sL = Vector([20144717174267243584247126412021907276793462846970539360059288107735610647945,15040251461887722561288264322239518061255819832348662582383129004704022603642,97933652316292946183399427450438981090933603347955321067107393057352730507837,395760878031994781938330167944309878346923484865345536819112065106106692942])
    sR = Vector([14124842355461766197909896783106869029133342296508845748032624852340316375340,89639162977678097723449966442832874662389269036341555414004405789707095321607,102334214897209200763475004672217056365567928242964950952587884298360981490106,13247131849273667472247323801717593363591932098368978066674658505575722586872])

    ###

    A = InnerProductCommitment(aL, aR, c=alpha, U=getNUMS(255))
    P_a = A.get_commitment()

    print(A.b)
    print(B.encode_pubkey(P_a, 'hex_compressed'))




if __name__ == '__main__':
    generate_proof()