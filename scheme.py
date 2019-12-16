from contextlib import contextmanager
from dataclasses import dataclass, fields
from typing import Any, Iterator, List

from crypto import asymetric, sharing, symetric
from utils import bytes_2_int, int_2_bytes


@dataclass
class User:
    username: str
    private_key_bytes: bytes
    public_key_bytes: bytes

    def __eq__(self: "User", other: Any) -> bool:
        if not isinstance(other, User):
            return False
        if self.username != other.username:
            return False
        self_public_key = asymetric.deserialize_public_key(self.public_key_bytes)
        other_public_key = asymetric.deserialize_public_key(other.public_key_bytes)
        if self_public_key.public_numbers() != other_public_key.public_numbers():
            return False
        return True

    @staticmethod
    def new(username: str, password: bytes) -> "User":
        return User(username, *asymetric.new_key_pair(password))


@dataclass
class Key:
    user: User
    asymetric_locked: bytes


_DEFAULT_PRIME = 2 ** 127 - 1  # 12th Mersenne Prime, 13th is 2**521 - 1


@dataclass
class Secret:
    symetric_locked: bytes
    min_keys: int
    shared_keys: List[List[Key]]
    prime: int = _DEFAULT_PRIME
    scrypt_cfg: symetric.ScryptCfg = symetric.ScryptCfg()


@dataclass
class Content:
    payload: str
    shares: List[List[User]]
    min_shares: int


def decrypt_secret(secret: Secret, user: User, password: bytes) -> str:
    keys = {
        position: bytes_2_int(
            asymetric.decrypt(key.asymetric_locked, user.private_key_bytes, password)
        )
        for position, keys in enumerate(secret.shared_keys, start=1)
        for key in keys
        if key.user == user
    }
    assert (
        len(keys) >= secret.min_keys
    ), f"Not enough keys to open this secret ({len(keys)} < {secret.min_keys})."
    secret_key = int_2_bytes(sharing.recover_from_shares(keys, secret.prime))
    return symetric.decrypt(
        secret.symetric_locked, secret_key, secret.scrypt_cfg
    ).decode()


def encrypt_secret(content: Content, prime: int = _DEFAULT_PRIME) -> Secret:
    scrypt_cfg = symetric.ScryptCfg()
    min_keys = content.min_shares
    secret_key, shares = sharing.create_shares(min_keys, len(content.shares), prime)
    symetric_locked = symetric.encrypt(
        content.payload.encode(), int_2_bytes(secret_key), scrypt_cfg
    )
    shared_keys = [
        [
            Key(
                user=user,
                asymetric_locked=asymetric.encrypt(
                    int_2_bytes(shares[position]), user.public_key_bytes
                ),
            )
            for user in users
        ]
        for position, users in enumerate(content.shares, start=1)
    ]
    return Secret(
        symetric_locked=symetric_locked,
        min_keys=min_keys,
        shared_keys=shared_keys,
        prime=prime,
        scrypt_cfg=scrypt_cfg,
    )


@contextmanager
def open_secret(secret: Secret, user: User, password: bytes) -> Iterator[Content]:
    content = Content(
        payload=decrypt_secret(secret, user, password),
        shares=[[key.user for key in keys] for keys in secret.shared_keys],
        min_shares=secret.min_keys,
    )
    yield content
    new_secret = encrypt_secret(content)
    for field in fields(secret):
        setattr(secret, field.name, getattr(new_secret, field.name))
