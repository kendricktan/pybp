import hashlib
import pybitcointools as B

from typing import Tuple
from pybp.types import Vector


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


def inner_product(a: Vector, b: Vector) -> int:
    ret = 0

    if len(a) is not len(b):
        raise Exception(
            'inner_product between two vectors must be of same length')

    for i in range((len(a))):
        ret = ret + (a.n[i] * b.n[i])

    return ret


def halves(v: Vector) -> Vector:
    assert len(v) % 2 == 0
    h = int(len(v) / 2)
    return (v[:h], v[h:])


def getNUMS(index=0) -> bytes:
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

    The NUMS generator generated is returned as a secp256k1.PublicKey.
    """
    assert 0 <= index < 256

    for G in [B.encode_pubkey(B.G, 'bin_compressed'), B.encode_pubkey(B.G, 'bin')]:
        seed = G + chr(index).encode('utf-8')
        for counter in range(256):
            seed_c = seed + chr(counter).encode('utf-8')
            hash_seed = hashlib.sha256(seed_c).digest()

            # Every x-coord on the curve has two y-values, encoded
            # in compressed form with 02/03 parity byte. We just
            # choose the former
            claimed_point: bytes = b'\x02' + hash_seed

            if B.is_pubkey(claimed_point):
                return claimed_point

    raise Exception('NUMS generation inconceivable')
