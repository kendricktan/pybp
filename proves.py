import pybitcointools as B

from pybp.pederson import PedersonCommitment
from pybp.vectors import to_powervector, Vector
from pybp.utils import get_blinding_value, get_blinding_vector, getNUMS

"""
Section 3: A zero knowledge argument of knowledge of a set of vectors
"""
 
H = getNUMS(255)
N = 4

# P -> V: C_0
r = get_blinding_vector(N)
x = get_blinding_vector(N)

commitments = [
    PedersonCommitment(x[i], b=r[i]).get_commitment() for i in range(N)
]

# V -> P: e
e = get_blinding_value()
ev = to_powervector(e, N)

# P -> V (z, s)

# P
P = commitments[0]
for i in range(1, N):
    P = B.add_pubkeys(
        B.multiply(commitments[i], ev[i]),
        P
    )

z = ev * x
s = ev @ r

V = B.multiply(H, s)
for i in range(N):
    V = B.add_pubkeys(
        B.multiply(B.G, z[i]),
        V
    )

assert V == P