import pytest

import vault


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
                keys=[vault.Key.new(1, vault.User.new("u1", b"pass1")),],
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