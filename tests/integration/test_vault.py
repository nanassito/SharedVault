import pytest
from cryptography.fernet import InvalidToken

from sharedvault import vault


def test_new_secret():
    me = vault.User.new("u1", b"pass1")
    original = vault.Content(
        name="secret",
        payload="This is a very important and secret message.",
        min_keys=2,
        total_keys=3,
        keys=[
            vault.Key.new(1, me),
            vault.Key.new(2, me),
            vault.Key.new(2, vault.User.new("u3", b"pass2")),
            vault.Key.new(3, vault.User.new("u4", b"pass3")),
        ],
    )
    secret = vault.Secret.new(original)
    with secret.open(me, b"pass1") as content:
        assert content == original


@pytest.mark.parametrize(
    ("content",),
    [
        (  # Too many keys
            vault.Content(
                name="secret",
                payload="This is a very important and secret message.",
                min_keys=1,
                total_keys=2,
                keys=[
                    vault.Key.new(1, vault.User.new("u1", b"pass1")),
                    vault.Key.new(2, vault.User.new("u3", b"pass2")),
                    vault.Key.new(3, vault.User.new("u4", b"pass3")),
                ],
            ),
        ),
        (  # Min key too high
            vault.Content(
                name="secret",
                payload="This is a very important and secret message.",
                min_keys=4,
                total_keys=3,
                keys=[
                    vault.Key.new(1, vault.User.new("u1", b"pass1")),
                    vault.Key.new(2, vault.User.new("u3", b"pass2")),
                    vault.Key.new(3, vault.User.new("u4", b"pass3")),
                ],
            ),
        ),
        (  # Not enough keys
            vault.Content(
                name="secret",
                payload="This is a very important and secret message.",
                min_keys=2,
                total_keys=3,
                keys=[vault.Key.new(1, vault.User.new("u1", b"pass1"))],
            ),
        ),
    ],
)
def test_bad_secret_creation(content):
    with pytest.raises(AssertionError):
        vault.Secret.new(content)


def test_modify_secret():
    password = b"pass1"
    me = vault.User.new("u1", password)
    final_msg = "This is the new message"
    original = vault.Content(
        name="secret",
        payload="This is a very important and secret message.",
        min_keys=2,
        total_keys=3,
        keys=[vault.Key.new(i, me) for i in range(1, 4)],
    )
    secret = vault.Secret.new(original)
    with secret.open(me, password) as content:
        content.payload = final_msg
    with secret.open(me, password) as content:
        assert content.payload == final_msg


def test_store_secret():
    db = vault.get_db("sqlite:///:memory:")
    password = b"pass1"
    user = vault.User.new("username", password)
    secret_name = "secret"
    content = vault.Content(
        name=secret_name,
        payload="This is a very important and secret message.",
        min_keys=2,
        total_keys=3,
        keys=[vault.Key.new(i, user) for i in range(1, 4)],
    )
    secret = vault.Secret.new(content)
    db.add(secret)
    db.commit()
    with db.query(vault.Secret).get(secret_name).open(user, password) as data:
        assert data.payload == content.payload


def test_change_password():
    user = vault.User.new("username", b"pass1")
    secret_name = "secret"
    content = vault.Content(
        name=secret_name,
        payload="This is a very important and secret message.",
        min_keys=2,
        total_keys=3,
        keys=[vault.Key.new(i, user) for i in range(1, 4)],
    )
    secret = vault.Secret.new(content)
    user.change_password(b"pass1", b"pass2")
    with secret.open(user, b"pass2") as data:
        assert data.payload == content.payload


def test_authorize_user():
    user1 = vault.User.new("user1", b"pass1")
    user2 = vault.User.new("user2", b"pass2")
    secret_name = "secret"
    original = vault.Content(
        name=secret_name,
        payload="This is a very important and secret message.",
        min_keys=3,
        total_keys=4,
        keys=[
            vault.Key.new(1, user1),
            vault.Key.new(2, user1),
            vault.Key.new(3, user2),
            vault.Key.new(4, user2),
        ],
    )
    secret = vault.Secret.new(original)
    secret.authorize_user(user1, b"pass1", user2)
    with secret.open(user2, b"pass2") as content:
        assert content.payload == original.payload
    with pytest.raises((ValueError, AssertionError, InvalidToken)):
        with secret.open(user1, b"pass1"):
            pass


@pytest.mark.parametrize(
    ("min_keys", "username", "password"),
    [
        (1, "user2", b"wrong_passwd"),  # Wrong password
        (3, "user2", b"pass2"),  # Not enough shares
        (2, "user0", b"pass0"),  # No shares at all
    ],
)
def test_unlocking_failures(min_keys, username, password):
    users = {
        f"user{idx}": vault.User.new(f"user{idx}", f"pass{idx}".encode())
        for idx in range(4)
    }
    secret_name = "secret"
    original = vault.Content(
        name=secret_name,
        payload="This is a very important and secret message.",
        min_keys=min_keys,
        total_keys=6,
        keys=[
            vault.Key.new(1, users["user1"]),
            vault.Key.new(2, users["user2"]),
            vault.Key.new(3, users["user2"]),
            vault.Key.new(4, users["user3"]),
            vault.Key.new(5, users["user3"]),
            vault.Key.new(6, users["user3"]),
        ],
    )
    secret = vault.Secret.new(original)
    with pytest.raises((ValueError, AssertionError, InvalidToken)):
        with secret.open(username, password):
            pass
