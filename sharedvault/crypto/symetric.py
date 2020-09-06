f"""This implement simple wrapping function to provide symetric encryption."""
import json
import os
from base64 import b64decode, b64encode, urlsafe_b64encode
from dataclasses import dataclass, field
from hashlib import scrypt

from cryptography import fernet

from utils import dataclass_to_dict


@dataclass
class ScryptCfg:
    # TODO: Read up on how to strengthen this.
    salt: bytes = field(default_factory=lambda: os.urandom(16))
    n: int = 16384
    r: int = 8
    p: int = 1
    dklen: int = 32

    @staticmethod
    def from_json(raw: str) -> "ScryptCfg":
        data = json.loads(raw)
        return ScryptCfg(
            salt=b64decode(data["salt"].encode()),
            n=int(data["n"]),
            r=int(data["r"]),
            p=int(data["p"]),
            dklen=int(data["dklen"]),
        )

    def to_json(self: "ScryptCfg") -> str:
        return json.dumps(
            {
                "salt": b64encode(self.salt).decode(),
                "n": self.n,
                "r": self.r,
                "p": self.p,
                "dklen": self.dklen,
            },
            sort_keys=True,
        )


def _derive_key(secret: bytes, scrypt_cfg: ScryptCfg) -> bytes:
    return urlsafe_b64encode(scrypt(secret, **dataclass_to_dict(scrypt_cfg)))


def encrypt(payload: bytes, password: bytes, scrypt_cfg: ScryptCfg) -> bytes:
    key = _derive_key(password, scrypt_cfg)
    return fernet.Fernet(key).encrypt(payload)


def decrypt(payload: bytes, password: bytes, scrypt_cfg: ScryptCfg) -> bytes:
    key = _derive_key(password, scrypt_cfg)
    return fernet.Fernet(key).decrypt(payload)
