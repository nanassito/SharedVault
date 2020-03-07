"""Cli to store and manipulate `Secret`s and their `Content`."""

import logging
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List

from sqlalchemy import Binary, Column, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, session, sessionmaker

import utils
from sharedvault.crypto import asymetric, sharing, symetric

Base = declarative_base()
_DEFAULT_PRIME = 2 ** 127 - 1  # 12th Mersenne Prime, 13th is 2**521 - 1
_LOG = logging.getLogger(__name__)


@dataclass
class Content:
    name: str
    payload: str
    min_keys: int
    total_keys: int
    keys: List["Key"]


class User(Base):  # type: ignore
    __tablename__ = "users"

    username = Column(String, primary_key=True)
    private_key_bytes = Column(Binary, nullable=False)
    public_key_bytes = Column(Binary, nullable=False)

    keys: List["Key"]

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
        priv, pub = asymetric.new_key_pair(password)
        _LOG.debug(f"Creating new user {username} with public key {pub.decode()}")
        return User(username=username, private_key_bytes=priv, public_key_bytes=pub)

    def change_password(self: "User", old_password: bytes, new_password: bytes) -> None:
        keys_unlocked = asymetric.decrypt_batch(
            [key.asymetric_locked for key in self.keys],
            self.private_key_bytes,
            old_password,
        )
        new_priv, new_pub = asymetric.new_key_pair(new_password)
        _LOG.debug(f"Generated to key pair for {self.username}: {new_pub.decode()}")
        for key, unlocked in zip(self.keys, keys_unlocked):
            _LOG.debug(f"Updating the key {key.position} in `{key.secret_name}`")
            key.asymetric_locked = asymetric.encrypt(unlocked, new_pub)
        self.public_key_bytes = new_pub
        self.private_key_bytes = new_priv


class Secret(Base):  # type: ignore
    __tablename__ = "secrets"

    name = Column(String, primary_key=True, nullable=False)
    symetric_locked = Column(Binary, nullable=False)
    min_keys = Column(Integer, nullable=False)
    total_keys = Column(Integer, nullable=False)
    prime = Column(Binary, nullable=False)  # Too big to be stored as a number
    scrypt_cfg_json = Column(Text, nullable=False)

    shared_keys: List["Key"]

    @staticmethod
    def new(content: Content) -> "Secret":
        secret = Secret()
        secret.encrypt(content)
        return secret

    def decrypt(self: "Secret", user: User, password: bytes) -> str:
        if not self.symetric_locked:
            return ""
        keys: Dict[int, int] = {}
        for key in self.shared_keys:
            if key.position in keys:
                continue
            if key.user == user:
                _LOG.debug(f"Unlocking key at position {key.position}")
                keys[key.position] = utils.bytes_2_int(
                    asymetric.decrypt(
                        key.asymetric_locked, user.private_key_bytes, password
                    )
                )
        assert (
            len(keys) >= self.min_keys
        ), f"Not enough keys to open this secret ({len(keys)} < {self.min_keys})."
        _LOG.info(f"Recovering encryption key from {len(keys)} shares")
        secret_key = utils.int_2_bytes(
            sharing.recover_from_shares(keys, utils.bytes_2_int(self.prime))
        )
        _LOG.info(f"Decrypting `{self.name}`")
        return symetric.decrypt(
            self.symetric_locked,
            secret_key,
            symetric.ScryptCfg.from_json(self.scrypt_cfg_json),
        ).decode()

    def encrypt(self: "Secret", content: Content) -> None:
        key_positions = {k.position for k in content.keys}
        assert (
            content.min_keys <= len(key_positions) <= content.total_keys
        ), f"{content.min_keys=} <= {len(key_positions)=} <= {content.total_keys=}"
        assert 0 not in key_positions, "Can't have keys at position 0"
        self.name = content.name
        self.min_keys = content.min_keys
        self.total_keys = content.total_keys
        self.prime = utils.int_2_bytes(_DEFAULT_PRIME)
        _LOG.info(
            f"Creating a new scrypt configuration for the secret (including new salt)."
        )
        scrypt_cfg = symetric.ScryptCfg()
        self.scrypt_cfg_json = scrypt_cfg.to_json()

        _LOG.info(
            f"Generating new encryption key and associated {self.total_keys} "
            f"shares with a minimum of {self.min_keys} shares needed for recovery."
        )
        secret_key, shares = sharing.create_shares(
            self.min_keys, self.total_keys, utils.bytes_2_int(self.prime)
        )
        _LOG.info("Encrypting the secret.")
        self.symetric_locked = symetric.encrypt(
            content.payload.encode(), utils.int_2_bytes(secret_key), scrypt_cfg
        )
        self.shared_keys = content.keys
        for key in self.shared_keys:
            _LOG.debug(
                f"Encrypting key {key.position} with {key.user.username}'s public key."
            )
            key.asymetric_locked = asymetric.encrypt(
                utils.int_2_bytes(shares[key.position]), key.user.public_key_bytes
            )
        _LOG.info("Locked all keys for the secret")

    @contextmanager
    def open(self: "Secret", user: User, password: bytes) -> Iterator[Content]:
        content = Content(
            name=self.name,
            payload=self.decrypt(user, password),
            keys=self.shared_keys,
            min_keys=self.min_keys,
            total_keys=self.total_keys,
        )
        yield content
        self.encrypt(content)

    def authorize_user(
        self: "Secret", grantor: User, password: bytes, grantee: User
    ) -> None:
        new_keys = []
        for key in self.shared_keys:
            if key.user == grantor:
                _LOG.debug(
                    f"Encrypting key {key.position} with {grantee.username}'s public key."
                )
                new_key = Key(
                    user=grantee,
                    secret=self,
                    position=key.position,
                    asymetric_locked=asymetric.encrypt(
                        asymetric.decrypt(
                            key.asymetric_locked, grantor.private_key_bytes, password
                        ),
                        grantee.public_key_bytes,
                    ),
                )
                new_keys.append(new_key)
        self.shared_keys += new_keys
        _LOG.info(
            f"Authorized {grantee.username} to open {grantor.username}'s keys "
            f"for {self.name}'"
        )


class Key(Base):  # type: ignore
    __tablename__ = "keys"

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    position = Column(Integer, nullable=False)
    username = Column(ForeignKey("users.username"), nullable=False)
    secret_name = Column(ForeignKey("secrets.name"), nullable=False)
    asymetric_locked = Column(Binary, nullable=False)

    user = relationship("User", back_populates="keys")
    secret = relationship("Secret", back_populates="shared_keys")

    @staticmethod
    def new(position: int, user: User) -> "Key":
        """Create a new Key for a new or existing Secret."""
        assert position != 0, "Can't have keys at position 0."
        return Key(position=position, user=user)


User.keys = relationship("Key", back_populates="user")
Secret.shared_keys = relationship("Key", back_populates="secret")


def get_db(connection_string: str, show_sql: bool = False) -> session.Session:
    engine = create_engine(connection_string, echo=show_sql)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False)()
