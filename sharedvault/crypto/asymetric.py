"""This implement simple wrapping function to provide asymetric encryption."""
from typing import List, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def serialize_private_key(private_key: _RSAPrivateKey, password: bytes) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )


def deserialize_private_key(
    private_key_bytes: bytes, password: bytes
) -> _RSAPrivateKey:
    return serialization.load_pem_private_key(
        private_key_bytes, password=password, backend=default_backend()
    )


def serialize_public_key(public_key: _RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1
    )


def deserialize_public_key(public_key_bytes: bytes) -> _RSAPublicKey:
    return serialization.load_pem_public_key(
        public_key_bytes, backend=default_backend()
    )


def new_key_pair(password: bytes) -> Tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_key_bytes = serialize_private_key(private_key, password)
    public_key = private_key.public_key()
    public_key_bytes = serialize_public_key(public_key)
    return private_key_bytes, public_key_bytes


_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def decrypt_batch(
    secrets: List[bytes], private_key_bytes: bytes, password: bytes
) -> List[bytes]:
    private_key = deserialize_private_key(private_key_bytes, password)
    return [private_key.decrypt(secret, _PADDING) for secret in secrets]


def decrypt(secret: bytes, private_key_bytes: bytes, password: bytes) -> bytes:
    return decrypt_batch([secret], private_key_bytes, password)[0]


def encrypt(secret: bytes, public_key_bytes: bytes) -> bytes:
    public_key = deserialize_public_key(public_key_bytes)
    return public_key.encrypt(secret, _PADDING)
