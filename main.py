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
from pybp.rangeproof import RangeProof

value = -1
rangebits = 32


# now simulating: the serialized proof passed to the validator/receiver;
# note that it is tacitly assumed that in the expected application (CT
# or similar), the V value is a pedersen commitment which already exists
# in the transaction; it's what we're validating *against*, so it's not
# part of the proof itself. Hence we just pass rp.V into the verify call,
# for the case of valid rangeproofs.
print("Starting rangeproof test for value: ", value,
          " in range from 0 to 2^", rangebits)
fail = False
if not (0 < value and value < 2**rangebits):
    print("Value is NOT in range; we want verification to FAIL.")
    fail = True
    #To attempt to forge a rangeproof for a not-in-range value,
    #we'll do the following: make a *valid* proof for the truncated
    #bits of our overflowed value, and then apply a V pedersen commitment
    #to our actual value, which will (should!) fail.
    #Obviously, there are a near-infinite number of ways to create
    #invalid proofs, TODO look into others.
    proofval = value & (2**rangebits -1)
    print("Using truncated bits, value: ", proofval, " to create fake proof.")
else:
    proofval = value
rp = RangeProof(rangebits)
rp.generate_proof(proofval)
proof = rp.get_proof_dict()
#now simulating: the serialized proof passed to the validator/receiver;
#note that it is tacitly assumed that in the expected application (CT
#or similar), the V value is a pedersen commitment which already exists
#in the transaction; it's what we're validating *against*, so it's not
#part of the proof itself. Hence we just pass rp.V into the verify call,
#for the case of valid rangeproofs.
#Note this is a new RangeProof object:
rp2 = RangeProof(rangebits)

print("Now attempting to verify a proof in range: 0 -", 2**rangebits)
if fail:
    #As mentioned in comments above, here create a Pedersen commitment
    #to our actual value, which is out of range, with the same blinding
    #value.
    Varg = PedersonCommitment(value, b=rp.gamma).get_commitment()
else:
    Varg = rp.V
if not rp2.verify(
        proof['Ap'],
        proof['Sp'],
        proof['T1p'],
        proof['T2p'],
        proof['tau_x'],
        proof['mu'],
        proof['t'],
        proof['proof'],
        rp.V
    ):
    if not fail:
        print('Rangeproof should have verified but is invalid; bug.')
    else:
        print("Rangeproof failed, as it should because value is not in range.")
else:
    if not fail:
        print('Rangeproof verified correctly, as expected.')
    else:
        print("Rangeproof succeeded but it should not have, value is not in range; bug.")
