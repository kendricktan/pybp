import os
import hashlib
import pybitcointools as B
import coincurve as C

from typing import Tuple
from pybp.types import Scalar, Point
from pybp.vectors import Vector


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Distance

    return (g, x, y) such that a*x + b*y = g = gcd(x, y)
    """
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def modinv(a: int, m: int) -> int:
    """
    Modular Inverse

    returns x where a * x = 1 mod m
    """

    g, x, _ = egcd(a, m)
    if g is not 1:
        raise Exception('Modular Inverse does not exist!')
    return x % m


def getNUMS(index=0) -> Point:
    """
    Nothing Up My Sleeve

    Taking secp256k1's G as a seed,
    either in compressed or uncompressed form,
    append "index" as a byte, and append a second byte "counter"
    try to create a new NUMS base point from the sha256 of that
    bytestring. Loop counter and alternate compressed/uncompressed
    until finding a valid curve point. The first such point is
    considered as "the" NUMS base point alternative for this index value.
    The search process is of course deterministic/repeatable, so
    it's fine to just store a list of all the correct values for
    each index, but for transparency left in code for initialization
    by any user.
    """
    assert index in range(256)

    for G in [B.encode_pubkey(B.G, 'bin_compressed'), B.encode_pubkey(B.G, 'bin')]:
        # Using latin-1 since its used in BTC
        seed = G + chr(index).encode('latin-1')
        for counter in range(256):
            seed_c = seed + chr(counter).encode('latin-1')
            hash_seed = hashlib.sha256(seed_c).digest()

            # Every x-coord on the curve has two y-values, encoded
            # in compressed form with 02/03 parity byte. We just
            # choose the former
            claimed_point: bytes = chr(2).encode('latin-1') + hash_seed

            try:
                C.PublicKey(claimed_point)
                return B.encode_pubkey(claimed_point, 'decimal')
            except:
                continue

    raise Exception('NUMS generation inconceivable')


def get_blinding_value() -> Scalar:
    return B.encode_privkey(os.urandom(32), 'decimal')


def get_blinding_vector(length) -> Vector:
    return Vector([get_blinding_value() for i in range(length)])
