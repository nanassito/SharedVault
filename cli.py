from argparse import ArgumentParser
from collections import defaultdict
from inspect import signature
from typing import Callable, Dict, List, Set, TypeVar

from argparse_logging import add_logging_arguments
from sqlalchemy.orm import session
from tabulate import tabulate

import vault

T = TypeVar("T")


def cli_args(*args, **kwargs) -> Callable:
    def wrapped(func: T) -> T:
        if not isinstance(getattr(func, "args", None), list):
            setattr(func, "args", [])
        getattr(func, "args").append(
            lambda parser: parser.add_argument(*args, **kwargs)
        )
        return func

    return wrapped


def list_secrets(db: session.Session) -> None:
    print(
        tabulate(
            [
                {
                    "name": secret.name,
                    "min keys": secret.min_keys,
                    "total keys": secret.total_keys,
                }
                for secret in db.query(vault.Secret).all()
            ],
            headers="keys",
        )
    )


@cli_args("name", help="Name of the secret.")
def describe_secret(db: session.Session, name: str) -> None:
    secret = db.query(vault.Secret).get(name)
    print("Name:", secret.name)
    print("Minimum number of keys:", secret.min_keys)
    print("Total number of keys:", secret.total_keys)
    print("Key holders:")
    key_owners: Dict[str, Set[str]] = defaultdict(set)
    for key in secret.shared_keys:
        key_owners[key.user.username].add(str(key.position))
    print(
        tabulate(
            [
                {"Username": username, "Keys": ", ".join(sorted(positions))}
                for username, positions in sorted(key_owners.items())
            ],
            headers="keys",
        )
    )


@cli_args("password", type=lambda x: x.encode(), help="Your password.")
@cli_args("username", help="Your username.")
@cli_args("name", help="Name of the secret.")
def read_secret(db: session.Session, name: str, username: str, password: bytes) -> None:
    user = db.query(vault.User).get(username)
    secret = db.query(vault.Secret).get(name)
    with secret.open(user, password) as content:
        print(content.payload)


@cli_args("password", type=lambda x: x.encode(), help="Your password.")
@cli_args("username", help="Your username.")
@cli_args("name", help="Name of the secret.")
def delete_secret(
    db: session.Session, name: str, username: str, password: bytes
) -> None:
    user = db.query(vault.User).get(username)
    secret = db.query(vault.Secret).get(name)
    secret.decrypt(user, password)
    for key in secret.shared_keys:
        db.delete(key)
    db.delete(secret)
    db.commit()


@cli_args(
    "keys",
    nargs="+",
    type=lambda x: set(x.split(",")),
    help="Each key is a comma separated list of username that will hold that key.",
)
@cli_args(
    "min_keys", type=int, help="Minimum number of keys required to open the secret.",
)
@cli_args("payload", help="Content of the secret.")
@cli_args("name", help="Name of the secret.")
def new_secret(
    db: session.Session, name: str, payload: str, min_keys: int, keys: List[Set[str]]
) -> None:
    content = vault.Content(
        name=name,
        payload=payload,
        min_keys=min_keys,
        total_keys=len(keys),
        keys=[
            vault.Key.new(position, db.query(vault.User).get(username))
            for position, usernames in enumerate(keys, start=1)
            for username in usernames
        ],
    )
    secret = vault.Secret.new(content)
    db.add(secret)
    db.commit()


def list_users(db: session.Session) -> None:
    print(
        tabulate(
            [{"Username": user.username} for user in db.query(vault.User).all()],
            headers="keys",
        )
    )


@cli_args("password", type=lambda x: x.encode(), help="Password of the user.")
@cli_args("username", help="Name of the new user. Must be unique")
def new_user(db: session.Session, username: str, password: bytes) -> None:
    user = vault.User.new(username, password)
    db.add(user)
    db.commit()


# authorize_user


@cli_args("new_password", type=lambda x: x.encode(), help="New password of the user.")
@cli_args("old_password", type=lambda x: x.encode(), help="Old password of the user.")
@cli_args("username", help="Name of the new user. Must be unique")
def change_password(
    db: session.Session, username: str, old_password: bytes, new_password: bytes
) -> None:
    user = db.query(vault.User).get(username)
    user.change_password(old_password, new_password)
    db.merge(user)
    db.commit()


def main():
    parser = ArgumentParser(description=__doc__)
    add_logging_arguments(parser)
    parser.add_argument(
        "--db",
        default="sqlite:///vault.sqlite3",
        help="Database connection string",
        type=vault.get_db,
    )
    subparsers = parser.add_subparsers()
    for function in (
        delete_secret,
        describe_secret,
        list_secrets,
        list_users,
        new_secret,
        change_password,
        new_user,
        read_secret,
    ):
        subparser = subparsers.add_parser(function.__name__, help=function.__doc__)
        subparser.set_defaults(method=function)
        for add_argument in getattr(function, "args", []):
            add_argument(subparser)
    args = parser.parse_args()
    assert getattr(args, "method", False), "Need to specify what function to use."
    args.method(
        **{param: getattr(args, param) for param in signature(args.method).parameters}
    )


if __name__ == "__main__":
    main()
