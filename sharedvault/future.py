import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Generator, Iterator, List, NewType, Optional, Set, Type

from pgpy import PGPUID, PGPKey
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)
from primitize.core import primitize, primitized

Userid = NewType("Userid", str)
SecretId = NewType("SecretId", str)
BytesAsB64str = NewType("BytesAsB64str", str)
PgpArmoredMsg = NewType("PgpArmoredMsg", str)


@dataclass
class Vault:
    @dataclass
    class Secret:
        content: BytesAsB64str
        min_keys: int
        keys: List[PgpArmoredMsg]

    users: Dict[Userid, PGPKey] = primitized(
        modifier=lambda vault, users: [str(u) for _, u in sorted(users.items())]
    )
    secrets: Dict[SecretId, Secret]

    def create_user(self: "Vault", userid: Userid, password: str) -> None:
        assert userid not in self.users, f"Userid {userid} already exists."
        self.users[userid] = key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        key.add_uid(
            PGPUID.new(userid),
            usage={KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
        )
        key.protect(password, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    def import_user(
        self: "Vault", pem: Path, username: Optional[Userid] = None
    ) -> None:
        raise NotImplementedError()

    def list_users(self: "Vault") -> List[Userid]:
        return sorted(self.users.keys())

    def list_secrets(self: "Vault") -> List[SecretId]:
        return sorted(self.secrets.keys())

    def read_secret(self: "Vault", secretid: SecretId, key: PGPKey) -> str:
        assert secretid in self.secrets, f"Secret `{secretid}` doesn't exists"
        raise NotImplementedError()

    def write_secret(
        self: "Vault",
        secretid: SecretId,
        content: str,
        min_keys: int,
        keyholders: List[Set[Userid]],
    ) -> str:
        raise NotImplementedError()


@dataclass
class FileVault:
    location: Path

    @classmethod
    def create(cls: Type["FileVault"], location: Path) -> "FileVault":
        with location.open("w") as fd:
            json.dump(
                primitize(Vault(users={}, secrets={})), fd, sort_keys=True, indent=4
            )
        return cls(location)

    @contextmanager
    def open(self: "FileVault") -> Iterator[Vault]:
        with self.location.open() as fd:
            data = json.load(fd)
        user_keys = [PGPKey.from_blob(u) for u in data["users"]]
        vault = Vault(
            users={keys[0].userids[0].name: keys[0] for keys in user_keys},
            secrets={n: Secret(**s) for n, s in data["secrets"].items()},
        )
        yield vault
        with self.location.open("w") as fd:
            json.dump(primitize(vault), fd, sort_keys=True, indent=4)


if __name__ == "__main__":
    with FileVault(Path(__file__).parent.parent / "test.vault").open() as v:
        print(v)