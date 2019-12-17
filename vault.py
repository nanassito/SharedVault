"""Cli to store and manipulate `Secret`s and their `Content`."""

from dataclasses import fields
from itertools import chain
from typing import Dict, List

from sqlalchemy import Binary, Column, ForeignKey, Integer, String, Text, create_engine

# from argparse_logging import add_logging_arguments
from sqlalchemy.engine import Engine
from sqlalchemy.ext.declarative import declarative_base

# from argparse import ArgumentParser
from sqlalchemy.orm import relationship, sessionmaker
from tabulate import tabulate

import scheme
import utils
from crypto.symetric import ScryptCfg

Base = declarative_base()


class UserDBO(Base):  # type: ignore
    __tablename__ = "users"

    username = Column(String, primary_key=True)
    private_key_bytes = Column(Binary, nullable=False)
    public_key_bytes = Column(Binary, nullable=False)

    @staticmethod
    def from_User(user: scheme.User) -> "UserDBO":
        return UserDBO(**utils.dataclass_to_dict(user))

    def to_User(self: "UserDBO") -> scheme.User:
        return scheme.User(
            **{field.name: getattr(self, field.name) for field in fields(scheme.User)}
        )


class SecretDBO(Base):  # type: ignore
    __tablename__ = "secrets"

    name = Column(String, primary_key=True, nullable=False)
    symetric_locked = Column(Binary, nullable=False)
    min_keys = Column(Integer, nullable=False)
    total_keys = Column(Integer, nullable=False)
    prime = Column(Binary, nullable=False)
    scrypt_cfg_json = Column(Text, nullable=False)

    @staticmethod
    def from_Secret(secret: scheme.Secret) -> "SecretDBO":
        return SecretDBO(
            name=secret.name,
            symetric_locked=secret.symetric_locked,
            min_keys=secret.min_keys,
            total_keys=len(secret.shared_keys),
            prime=utils.int_2_bytes(secret.prime),
            scrypt_cfg_json=secret.scrypt_cfg.to_json(),
            keys=list(
                chain(
                    *[
                        [KeyDBO.from_Key(secret, position, key) for key in keys]
                        for position, keys in secret.shared_keys.items()
                    ]
                )
            ),
        )

    def to_Secret(self: "SecretDBO") -> scheme.Secret:
        shared_keys: Dict[int, List[scheme.Key]] = {
            position: [] for position in range(1, self.total_keys + 1)
        }
        for key in self.keys:
            shared_keys[key.position].append(key.to_Key())
        return scheme.Secret(
            name=self.name,
            symetric_locked=self.symetric_locked,
            min_keys=self.min_keys,
            shared_keys=dict(shared_keys),
            prime=utils.bytes_2_int(self.prime),
            scrypt_cfg=ScryptCfg.from_json(self.scrypt_cfg_json),
        )


class KeyDBO(Base):  # type: ignore
    __tablename__ = "keys"

    position = Column(Integer, primary_key=True, nullable=False)
    username = Column(ForeignKey("users.username"), primary_key=True, nullable=False)
    secret_name = Column(ForeignKey("secrets.name"), primary_key=True, nullable=False)
    asymetric_locked = Column(Binary, nullable=False)

    user = relationship("UserDBO", back_populates="keys")
    secret = relationship("SecretDBO", back_populates="keys")

    @staticmethod
    def from_Key(secret: scheme.Secret, position: int, key: scheme.Key) -> "KeyDBO":
        return KeyDBO(
            position=position,
            username=key.user.username,
            secret_name=secret.name,
            asymetric_locked=key.asymetric_locked,
        )

    def to_Key(self: "KeyDBO") -> scheme.Key:
        assert (
            self.user is not None
        ), "Couldn't look up the user, the FK is probably messed up."
        return scheme.Key(
            user=self.user.to_User(), asymetric_locked=self.asymetric_locked
        )


UserDBO.keys = relationship("KeyDBO", back_populates="user")
SecretDBO.keys = relationship("KeyDBO", back_populates="secret")


# list_secrets
# read_secret
# update_secret
# delete_secret
# new_secret


def list_users(db):
    users = [user_dbo.to_User() for user_dbo in db.query(UserDBO).all()]
    print(
        tabulate(
            headers=("Username",), tabular_data=[(user.username,) for user in users]
        )
    )


# new_user
# authorize_user
# change_password


# engine = create_engine("sqlite:///:memory:", echo=True)
# Session = sessionmaker(bind=engine)
# Base.metadata.create_all(engine)

# u = scheme.User.new("dorian", b"password")
# s1 = scheme.encrypt_secret(
#     scheme.Content(
#         name="my secret",
#         payload="This is super secret.",
#         min_shares=2,
#         shares={1: [u], 2: [u], 3: []},
#     )
# )
# session = Session()
# session.add(UserDBO.from_User(u))
# session.add(SecretDBO.from_Secret(s1))
# session.commit()
# s2 = session.query(SecretDBO).first().to_Secret()
# print(
#     {
#         field.name: getattr(s1, field.name) == getattr(s2, field.name)
#         for field in fields(scheme.Secret)
#     }
# )
