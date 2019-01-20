from .types import Vector


def inner_product(a: Vector, b: Vector) -> int:
    ret = 0

    if len(a) is not len(b):
        raise Exception(
            'inner_product between two vectors must be of same length')

    for i in range((len(a))):
        ret = ret + (a.n[i] * b.n[i])

    return ret
