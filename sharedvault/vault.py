import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Generator, Iterator, List, NewType, Optional, Set, Type

from pgpy import PGPUID, PGPKey, PGPMessage
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)
from primitize.core import primitize, primitized
from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode


Userid = NewType("Userid", str)
SecretId = NewType("SecretId", str)
BytesAsB64str = NewType("BytesAsB64str", str)
PgpArmoredMsg = NewType("PgpArmoredMsg", str)


@dataclass
class Vault:
    @dataclass
    class Secret:
        content: BytesAsB64str
        aes_nonce: BytesAsB64str
        aes_tag: BytesAsB64str
        min_keys: int
        keys: List[PgpArmoredMsg] = primitized(
            modifier=lambda secret, keys: [str(key) for key in keys]
        )

    users: Dict[Userid, PGPKey] = primitized(
        modifier=lambda vault, users: [str(u) for _, u in sorted(users.items())]
    )
    secrets: Dict[SecretId, Secret] = primitized(
        modifier=lambda vault, secrets: {
            secret_id: primitize(secret) for secret_id, secret in secrets.items()
        }
    )

    @staticmethod
    def _add_uid_to_pgp_key(key: PGPKey, userid: Userid) -> None:
        key.add_uid(
            PGPUID.new(userid),
            usage={KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
        )

    def create_user(self: "Vault", userid: Userid, password: str) -> None:
        assert userid not in self.users, f"Userid {userid} already exists."
        self.users[userid] = key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        Vault._add_uid_to_pgp_key(key, userid)
        key.protect(password, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        del password

    def import_user(
        self: "Vault", pem: Path, username: Optional[Userid] = None
    ) -> None:
        self.users[userid] = key = PGPKey.from_file(pem)[0]
        key.del_uid("")
        Vault._add_uid_to_pgp_key(key, userid)

    @contextmanager
    def authenticate(self: "Vault", userid: Userid, password: str) -> Iterator[PGPKey]:
        with self.users[userid].unlock(password) as key:
            del password
            yield key

    def list_users(self: "Vault") -> List[Userid]:
        return sorted(self.users.keys())

    def list_secrets(self: "Vault") -> List[SecretId]:
        return sorted(self.secrets.keys())

    def read_secret(self: "Vault", secretid: SecretId, unlocked_key: PGPKey) -> str:
        assert secretid in self.secrets, f"Secret `{secretid}` doesn't exists"
        assert unlocked_key.is_unlocked, "The key must be unlocked first."
        secret = self.secrets[secretid]
        key_id = list(unlocked_key.userids[0].signers)[0]
        shares: List[Tuple[int, bytes]] = [
            (idx + 1, b64decode(unlocked_key.decrypt(msg).message))
            for idx, msg in enumerate(secret.keys)
            if key_id in msg.encrypters
        ]
        key = Shamir.combine(shares)
        cipher = AES.new(key, AES.MODE_EAX, b64decode(secret.aes_nonce))
        return cipher.decrypt_and_verify(
            b64decode(secret.content), b64decode(secret.aes_tag)
        ).decode()

    def write_secret(
        self: "Vault",
        secretid: SecretId,
        content: str,
        min_keys: int,
        shareholders: List[Set[Userid]],
    ) -> None:
        assert 0 < min_keys <= len(shareholders)
        key = get_random_bytes(16)

        # Encrypt shares
        shares = Shamir.split(min_keys, len(shareholders), key)
        keys = []
        for (_, share), holders in zip(shares, shareholders):
            assert holders, "A share must be assigned to at least one user."
            msg = PGPMessage.new(b64encode(share).decode())
            pgp_cipher = SymmetricKeyAlgorithm.AES256
            session_key = pgp_cipher.gen_key()
            for userid in holders:
                msg = self.users[userid].pubkey.encrypt(
                    msg, cipher=pgp_cipher, sessionkey=session_key
                )
            del session_key
            keys.append(msg)

        # Encrypt secret
        data_cipher = AES.new(key, AES.MODE_EAX)
        content: bytes = data_cipher.encrypt(content.encode())
        tag: bytes = data_cipher.digest()
        nonce: bytes = data_cipher.nonce
        self.secrets[secretid] = Vault.Secret(
            content=b64encode(content).decode(),
            aes_nonce=b64encode(nonce).decode(),
            aes_tag=b64encode(tag).decode(),
            min_keys=min_keys,
            keys=keys,
        )


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
        if not "userB" in v.users:
            v.create_user("userB", "passB")
        v.write_secret(
            "secretA", "salade de fruits", 2, [{"userA"}, {"userA", "userB"}]
        )
        with v.authenticate("userA", "passA") as key:
            print(v.read_secret("secretA", key))
        print("The end.")
