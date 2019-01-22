import random

# Prime number
p = 260978677425009836700364089744760003717

# Generator
g = random.randint(1, p - 1)


class Verifier:
    def __init__(self, p, g):
        self.p = p

        # Generator
        self.g = g

        # Secret number
        self.s = random.randint(1, p - 1)

        # Hiding Generator - order of q and subgroup of Z_p
        self.h = pow(self.g, self.s, self.p)

    def add(self, *commitments):
        """
        Multiplying values in the pedersen commitment is
        similar to adding the values together before
        committing them

        Proof:
        C(A) x C(B) = (g^A)(h^(r_A)) * (g^B)(h^(r_B)) mod p
                    = g^(A+B) * h^(r_A + r_B) mod p
                    = C(A+B)
        """
        cm = 1
        for c in commitments:
            cm = cm * c
        return cm % self.p

    def verify(self, c, x, *r) -> bool:
        r_sum = sum(r)

        res = (pow(self.g, x, self.p) * pow(self.h, r_sum, self.p)) % self.p

        if c == res:
            return True
        return False


class Prover:
    def __init__(self, p, g, h):
        self.p = p
        self.g = g
        self.h = h

    def commit(self, value):
        """
        C(x) = (g^x)*(h^r) mod p

        where h = (g^s) mod p
        """
        r = random.randint(1, self.p - 1)

        # Commit message
        c = (pow(self.g, value, self.p) * pow(self.h, r, self.p)) % self.p

        return c, r


# Values we want to commit and prove later on
value1 = 50
value2 = 42

# Verifier and prover
verifier = Verifier(p, g)
prover = Prover(p, g, verifier.h)

# Commit message
c1, r1 = prover.commit(value1)
c2, r2 = prover.commit(value2)

# Verify result
result1 = verifier.verify(c1, value1, r1)
result2 = verifier.verify(c2, value2, r2)

if result1:
    print('Verified commitment 1')
else:
    print('Commitment 1 unverified')

if result2:
    print('Verified commitment 2')
else:
    print('Commitment 2 unverified')

# Prove homomorphic property
c_sum = verifier.add(c1, c2)
value_sum = value1 + value2

result_sum = verifier.verify(c_sum, value_sum, r1, r2)

if result_sum:
    print('Verified homomorphic property')
else:
    print('Homomorphic property not verified')
