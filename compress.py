import random

import pybitcointools as B

from functools import reduce
from pybp.pederson import PedersonCommitment
from pybp.vectors import to_powervector, Vector
from pybp.utils import get_blinding_value, get_blinding_vector, getNUMS, modinv

"""
Section 5: Condensing a single vector
"""
N = 10

# Integers will be lower case
# Points will be upper case
# Vectors will be bolded

# Doing this to make sure the points are on the curve)
a_vec = [getNUMS(255+i) for i in range(5)]
a = [val for points in a_vec for val in points]

G = [getNUMS(i) for i in range(N)]

def aiGi(i_a, i_g):
    global a, G

    assert 2 * i_g - 2 >= 0
    assert 2 * i_a - 2 >= 0

    return B.add(
        B.multiply(G[2 * i_g - 2], a[2 * i_a - 2]),
        B.multiply(G[2 * i_g - 1], a[2 * i_a - 1]),
    )


def Ak(k):
    assert k in range(-4, 5)
    min_i = max(1, 1-k)
    max_i = min(5, 5-k)

    ret = aiGi(min_i + k, min_i)

    # Shift everything by 1 as we've already
    # done the first item
    for i in range(min_i + 1, max_i + 1):

        ret = B.add(
            ret,
            aiGi(i + k, i)
        )

    return ret


# Received challenge, x from Verifier
x = get_blinding_value()

a_prime = [
    [pow(x, i+1, B.N) * a[i*2] for i in range(0, 5)],
    [pow(x, i+1, B.N) * a[i*2 + 1] for i in range(0, 5)]
]

a_prime = [
    reduce(lambda acc, i: B.add(acc, i), a_prime[0]),
    reduce(lambda acc, i: B.add(acc, i), a_prime[1])
]

G_prime = [
    [B.multiply(G[i*2], modinv(pow(x, i+1, B.N))) for i in range(0, 5)],
    [B.multiply(G[i*2+1], modinv(pow(x, i+1, B.N))) for i in range(0, 5)]
]

G_prime = [
    reduce(lambda acc, i: B.add(acc, i), G_prime[0]),
    reduce(lambda acc, i: B.add(acc, i), G_prime[1])
]

A_prime = B.add(
    B.multiply(G_prime[0], a_prime[0]),
    B.multiply(G_prime[1], a_prime[1])
)

###

xk_Ak = B.multiply(
    Ak(-4),
    modinv(
        pow(x, 4, B.N)
    )
)

for k in range(-3, 5):
    xk_val = pow(x, abs(k), B.N)
    if k < 0:
        xk_val = modinv(xk_val)

    xk_Ak = B.add_pubkeys(
        xk_Ak,
        B.multiply(
            Ak(k),
            xk_val
        )
    )

assert xk_Ak == A_prime
