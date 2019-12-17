import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from scheme import Content, User, encrypt_secret
from vault import Base, SecretDBO, UserDBO


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", echo=True)
    Session = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    return Session()


def test_user_serialization(db):
    orig = User.new("usr", b"passwd")
    db.add(UserDBO.from_User(orig))
    db.commit()
    result = db.query(UserDBO).get("usr").to_User()
    assert orig == result


def test_secret_serialization(db):
    user = User.new("usr", b"passwd")
    db.add(UserDBO.from_User(user))
    orig = encrypt_secret(
        Content(
            name="secret",
            payload="this is confidential",
            min_shares=2,
            shares={1: [user], 2: [user], 3: []},
        ),
        23,
    )
    db.add(SecretDBO.from_Secret(orig))
    db.commit()
    result = db.query(SecretDBO).get("secret").to_Secret()
    assert orig == result
