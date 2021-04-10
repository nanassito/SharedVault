import os
from base64 import b64decode, b64encode
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, Iterator, NewType, Set

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

UserName = NewType("UserName", str)
SecretName = NewType("SecretName", str)
PubKey = NewType("PubKey", str)  # Gpg armored pem
PrivKey = NewType("PrivKey", str)  # Gpg armored pem
SecretKey = NewType("SecretKey", str)


@dataclass
class User:
    secret_keys: Dict[SecretName, Dict[int, SecretKey]]
    public_key_armored_pem: PubKey
    private_key_armored_pem: PrivKey

    @property
    def public_key(self: "User") -> _RSAPublicKey:
        return serialization.load_pem_public_key(
            b64decode(self.public_key_base64), backend=default_backend()
        )

    @dataclass
    class AuthenticatedUser:
        public: User
        private_key: _RSAPrivateKey

    @contextmanager
    def auth(self: "User", password: str) -> Iterator[AuthenticatedUser]:
        yield self.AuthenticatedUser(
            self,
            serialization.load_pem_private_key(
                b64decode(self.private_key_base64),
                password=password.encode(),
                backend=default_backend(),
            ),
        )


@dataclass
class ScryptCfg:
    salt: bytes = field(default_factory=lambda: os.urandom(16))
    n: int = 16384
    r: int = 8
    p: int = 1
    dklen: int = 32


@dataclass
class Secret:
    encrypted_content_base64: str
    min_keys: int
    total_keys: int
    scrypt_cfg = ScryptCfg


@dataclass
class BaseVault:
    users: Dict[UserName, User]
    secrets: Dict[SecretName, Secret]
