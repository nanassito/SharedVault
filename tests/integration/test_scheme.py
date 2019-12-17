from scheme import encrypt_secret, open_secret, Content, User
from copy import deepcopy


def test_new_secret():
    msg = "This is a very important and secret message."
    password = b"password"
    user = User.new("username", password)
    original = Content(
        name="ct1", payload=msg, shares={1: [user], 2: [user], 3: []}, min_shares=2
    )
    secret = encrypt_secret(original)
    with open_secret(secret, user, password) as content:
        assert content == original


def test_modify_secret():
    msg = "First message"
    final_msg = "This is the new message"
    password = b"password"
    user = User.new("username", password)
    secret = encrypt_secret(
        Content(
            name="ct1", payload=msg, shares={1: [user], 2: [user], 3: []}, min_shares=2
        )
    )
    original_secret = deepcopy(secret)
    with open_secret(secret, user, password) as content:
        content.payload = final_msg
    assert secret != original_secret
    with open_secret(secret, user, password) as content:
        assert content.payload == final_msg
