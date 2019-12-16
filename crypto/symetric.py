"""This implement simple wrapping function to provide symetric encryption."""
import os
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from hashlib import scrypt

from cryptography import fernet

from utils import dataclass_to_dict


@dataclass
class ScryptCfg:
    # TODO: Read up on how to strethen this.
    salt: bytes = os.urandom(16)
    n: int = 16384
    r: int = 8
    p: int = 1
    dklen: int = 32


def _derive_key(secret: bytes, scrypt_cfg: ScryptCfg) -> bytes:
    return urlsafe_b64encode(scrypt(secret, **dataclass_to_dict(scrypt_cfg)))


def encrypt(payload: bytes, password: bytes, scrypt_cfg: ScryptCfg) -> bytes:
    key = _derive_key(password, scrypt_cfg)
    return fernet.Fernet(key).encrypt(payload)


def decrypt(payload: bytes, password: bytes, scrypt_cfg: ScryptCfg) -> bytes:
    key = _derive_key(password, scrypt_cfg)
    return fernet.Fernet(key).decrypt(payload)
