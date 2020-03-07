"""Implementation of Shamir Secret Sharing algorythm.

Part of the code is taken strait out of the wikipedia page.
https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
"""

from typing import Dict, Tuple
import random


def _eval_at(poly, x, prime):
    """Evaluates polynomial (coefficient tuple) at x, used to generate a
    shamir pool in make_random_shares below.
    """
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum


def create_shares(minimum: int, total: int, prime: int) -> Tuple[int, Dict[int, int]]:
    """Generates a random shamir pool, returns the secret and the share points.
    """
    if minimum > total:
        raise ValueError("Pool secret would be irrecoverable.")
    rand_gen = random.SystemRandom()
    poly = [rand_gen.randint(0, prime) for i in range(minimum)]
    points = {i: _eval_at(poly, i, prime) for i in range(1, total + 1)}
    return poly[0], points


def _extended_gcd(a, b):
    """Division in integers modulus p means finding the inverse of the
    denominator modulo p and then multiplying the numerator by this
    inverse (Note: inverse of A is B such that A*B % p == 1) this can
    be computed via extended Euclidean algorithm
    http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
    """
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y


def _divmod(num, den, p):
    """Compute num / den modulo prime p

    To explain what this means, the return value will be such that
    the following is true: den * _divmod(num, den, p) % p == num
    """
    inv, _ = _extended_gcd(den, p)
    return num * inv


def _lagrange_interpolate(x, x_s, y_s, p):
    """Find the y-value for the given x, given n (x, y) points;
    k points will define a polynomial of up to kth order.
    """
    k = len(x_s)
    assert k == len(set(x_s)), "points must be distinct"

    def PI(vals):  # upper-case PI -- product of inputs
        accum = 1
        for v in vals:
            accum *= v
        return accum

    nums = []  # avoid inexact division
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
    den = PI(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p) for i in range(k)])
    return (_divmod(num, den, p) + p) % p


def recover_from_shares(shares: Dict[int, int], prime: int) -> int:
    if len(shares) < 2:
        raise ValueError("need at least two shares")
    x_s, y_s = zip(*list(shares.items()))
    return _lagrange_interpolate(0, x_s, y_s, prime)
