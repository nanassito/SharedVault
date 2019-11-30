"""
Keys is a small application to require multiple people to open a given secret.

A typical use case is to store your password manager's key and distribute the
passwords to trusted friends and family. If you forget your key, together these
people will be able to recover it for you.

This uses Shamir's secret sharing algorythm: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
Part of the source code is taken directly from that same wikipedia page.
"""

import functools
import json
import random
from argparse import ArgumentParser
from base64 import b64decode, b64encode, urlsafe_b64encode
from dataclasses import dataclass, fields
from hashlib import sha256
from pathlib import Path
from typing import Dict, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tabulate import tabulate

# 12th Mersenne Prime
# (for this application we want a known prime number as close as
# possible to our security level; e.g.  desired security level of 128
# bits -- too large and all the ciphertext is large; too small and
# security is compromised)
_PRIME = 2 ** 127 - 1
# 13th Mersenne Prime is 2**521 - 1

_RINT = functools.partial(random.SystemRandom().randint, 0)


def int_to_b64(i: int) -> str:
    return b64encode(hex(i)[2:].encode()).decode()


def b64_to_int(s: Union[bytes, str]) -> int:
    return int(b64decode(s), base=16)


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


def make_random_shares(minimum, shares, prime=_PRIME):
    """Generates a random shamir pool, returns the secret and the share points.
    """
    if minimum > shares:
        raise ValueError("Pool secret would be irrecoverable.")
    poly = [_RINT(prime) for i in range(minimum)]
    points = [(i, _eval_at(poly, i, prime)) for i in range(1, shares + 1)]
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


def recover_secret(shares, prime=_PRIME):
    """Recover the secret from share points (x, y points on the polynomial).
    """
    if len(shares) < 2:
        raise ValueError("need at least two shares")
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)


def sha(s: str) -> str:
    return sha256(s.encode()).hexdigest()


def generate_key(secret: str) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sha(secret).encode(),
        iterations=100000,
        backend=default_backend(),
    )
    key = urlsafe_b64encode(kdf.derive(secret.encode()))
    return Fernet(key)


def encrypt(secret: str, payload: str) -> str:
    fernet = generate_key(secret)
    return fernet.encrypt(payload.encode()).decode()


def dencrypt(secret: str, payload: str) -> str:
    fernet = generate_key(secret)
    return fernet.decrypt(payload.encode()).decode()


@dataclass
class Key:
    description: str
    min_num_keys: int
    payload: str


def get_secret_from_user() -> str:
    shares = set()
    while _in := input("Next password: ").strip():
        assert "_" in _in, "Invalid password format"
        position, password = _in.split("_", 1)
        shares.add((int(position), b64_to_int(password)))
    return int_to_b64(recover_secret(list(shares)))


class Store:
    def __init__(self: "Store", location: Path) -> None:
        self.location: Path = location
        self.data: Dict[str, Key] = {}
        if self.location.exists() and self.location.stat().st_size:
            with self.location.open() as fd:
                self.data = {k: Key(**v) for k, v in json.load(fd).items()}

    def __del__(self: "Store") -> None:
        payload = {
            index: {field.name: getattr(key, field.name) for field in fields(key)}
            for index, key in self.data.items()
        }
        with self.location.open("w") as fd:
            json.dump(payload, fd, sort_keys=True, indent=4)

    def list(self: "Store") -> None:
        print(
            tabulate(
                [(key.min_num_keys, key.description) for key in self.data.values()],
                ("Min keys", "Description"),
            )
        )

    def new(self: "Store") -> None:
        total_keys = min_keys = 0
        while True:
            _in = input("Total number of keys: ").strip()
            try:
                total_keys = int(_in)
            except ValueError:
                print("This is not a valid number.")
            if total_keys >= 2:
                break
            else:
                print("The total number of keys must be 2 or more.")
        while True:
            _in = input("Minimum number of keys: ").strip()
            try:
                min_keys = int(_in)
            except ValueError:
                print("This is not a valid number.")
            if 1 <= min_keys <= total_keys:
                break
            else:
                print(f"The minimum number of keys must be between 1 and {total_keys}.")
        secret, shares = make_random_shares(minimum=min_keys, shares=total_keys)
        self.data[sha(int_to_b64(secret))] = Key(
            description=input("Description: "),
            min_num_keys=min_keys,
            payload=encrypt(int_to_b64(secret), input("Content: ")),
        )
        print("Data saved.")
        print(
            f"Here is the list of passwords for this new Key. You'll need at "
            f"least {min_keys} to open this Key in the future."
        )
        print(
            "- "
            + "\n- ".join(
                [f"{position}_{int_to_b64(share)}" for position, share in shares]
            )
        )

    def read(self: "Store") -> None:
        secret = get_secret_from_user()
        key = self.data.get(sha(secret), None)
        assert key is not None, "No secret found."
        print(dencrypt(secret, key.payload))

    def write(self: "Store") -> None:
        secret = get_secret_from_user()
        key = self.data.get(sha(secret), None)
        assert key is not None, "No secret found."
        print(f"Content: {dencrypt(secret, key.payload)}")
        new_content = input("New content: ").strip()
        if new_content:
            key.payload = encrypt(secret, new_content)

    def delete(self: "Store") -> None:
        secret = get_secret_from_user()
        index = sha(secret)
        if index in self.data:
            del self.data[index]


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument(
        "--file",
        default=Path(__file__).parent / "data.kmn",
        type=Path,
        help="Location of the file storing the data.",
    )
    parser.add_argument("action", choices=["list", "new", "read", "write", "delete"])
    args = parser.parse_args()

    store = Store(args.file)
    getattr(store, args.action)()


if __name__ == "__main__":
    main()
