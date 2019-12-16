from itertools import combinations

from crypto import asymetric, sharing, symetric


def test_sharing():
    prime = 23
    secret, shares = sharing.create_shares(3, 5, prime)
    for qty in range(3, 6):
        for parts in combinations(shares.items(), qty):
            assert secret == sharing.recover_from_shares(dict(parts), prime)


def test_symetric():
    secret = b"This is super confidential !"
    password = b"SuperRobu$tPassw0rd"
    scrypt_cfg = symetric.ScryptCfg()
    encrypted = symetric.encrypt(secret, password, scrypt_cfg)
    assert secret == symetric.decrypt(encrypted, password, scrypt_cfg)


def test_asymetric_private_key_serialization():
    password = b"password"
    private_key_bytes, _ = asymetric.new_key_pair(password)
    private_key = asymetric.deserialize_private_key(private_key_bytes, password)
    serialized = asymetric.serialize_private_key(private_key, password)
    deserialized = asymetric.deserialize_private_key(serialized, password)
    assert private_key.private_numbers() == deserialized.private_numbers()


def test_asymetric_public_key_serialization():
    _, public_key_bytes = asymetric.new_key_pair(b"password")
    public_key = asymetric.deserialize_public_key(public_key_bytes)
    serialized = asymetric.serialize_public_key(public_key)
    deserialized = asymetric.deserialize_public_key(serialized)
    assert public_key.public_numbers() == deserialized.public_numbers()


def test_asymetric():
    private_key_bytes, public_key_bytes = asymetric.new_key_pair(b"password")
    secret = b"This is super confidential !"
    encrypted = asymetric.encrypt(secret, public_key_bytes)
    assert secret == asymetric.decrypt(encrypted, private_key_bytes, b"password")
