"""Cli too to manipulate a vault databse.

This allows you to create, list, modify, read, secrets and the users having holds on them.

Note that all the parameters must be passed on the command line except for
authentication information (username & password) which are read from stdin.
"""

import logging
from argparse import ArgumentParser
from collections import defaultdict
from getpass import getpass
from inspect import signature
from itertools import chain, combinations
from typing import Callable, Dict, List, Set, Tuple, TypeVar

from argparse_logging import add_logging_arguments
from sqlalchemy.orm import session
from tabulate import tabulate

from sharedvault import vault

T = TypeVar("T")
_LOG = logging.getLogger(__name__)


def get_user_password() -> Tuple[str, bytes]:
    username = input("Username: ")
    password = getpass().encode()
    return username, password


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
    assert secret is not None, f"No secret found under the name `{name}`"
    print("Name:", secret.name)
    print("Minimum number of keys:", secret.min_keys)
    print("Total number of keys:", secret.total_keys)
    print("\nKey holders:")
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
    print("\nOpening sequences:")
    sequences = []
    for length in range(1, len(key_owners)):
        for owners in combinations(key_owners, length):
            if len(set(chain(*[key_owners[o] for o in owners]))) >= secret.min_keys:
                sequences.append(set(sorted(owners)))
    potential_duplicates = [s for s in sequences]
    while potential_duplicates:
        potential_duplicate = potential_duplicates.pop()
        is_dup = False
        for sequence in sequences:
            if sequence != potential_duplicate and sequence.issubset(
                potential_duplicate
            ):
                is_dup = True
                break
        if is_dup:
            sequences.remove(potential_duplicate)
    print(
        "* "
        + "\n* ".join(
            [
                ", ".join(sorted(o))
                for o in sorted(sequences, key=lambda s: (len(s), sorted(s)))
            ]
        )
    )


@cli_args("name", help="Name of the secret.")
def read_secret(db: session.Session, name: str) -> None:
    username, password = get_user_password()
    user = db.query(vault.User).get(username)
    assert user is not None, f"No such user `{username}`"
    secret = db.query(vault.Secret).get(name)
    assert secret is not None, f"No secret found under the name `{name}`"
    with secret.open(user, password) as content:
        print(content.payload)


@cli_args("name", help="Name of the secret.")
def delete_secret(db: session.Session, name: str) -> None:
    secret = db.query(vault.Secret).get(name)
    if secret is None:
        _LOG.warning(f"Secret {name} doesn't exists.")
        return
    for key in secret.shared_keys:
        db.delete(key)
    db.delete(secret)
    db.commit()
    _LOG.info(f"Deleted secret {name}")


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
    _LOG.info(f"Secret {name} saved to the databse.")


def list_users(db: session.Session) -> None:
    print(
        tabulate(
            [{"Username": user.username} for user in db.query(vault.User).all()],
            headers="keys",
        )
    )


def new_user(db: session.Session) -> None:
    username, password = get_user_password()
    user = vault.User.new(username, password)
    db.add(user)
    db.commit()
    _LOG.info(f"New user {username} saved to the databse.")


@cli_args("grantee_username", help="Username to authorize reading the secret.")
@cli_args("secret_name", help="Name of the secret to grant access to.")
def authorize_user(
    db: session.Session, secret_name: str, grantee_username: str
) -> None:
    grantee = db.query(vault.User).get(grantee_username)
    assert grantee is not None, f"Unknown user {grantee_username}"
    grantor_username, password = get_user_password()
    grantor = db.query(vault.User).get(grantor_username)
    assert grantor is not None, f"Unknown user {grantor_username}"
    secret = db.query(vault.Secret).get(secret_name)
    assert secret is not None, f"No secret found under the name `{secret_name}`"
    secret.authorize_user(grantor, password, grantee)
    db.merge(secret)
    db.commit()
    _LOG.info(
        f"Authorization of {grantee_username} by {grantor_username} for "
        f"`{secret_name}` saved to the database."
    )


def change_password(db: session.Session) -> None:
    username, old_password = get_user_password()
    new_password = getpass("New password: ").encode()
    user = db.query(vault.User).get(username)
    assert user is not None, f"Unknown user {username}"
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
        authorize_user,
        change_password,
        delete_secret,
        describe_secret,
        list_secrets,
        list_users,
        new_secret,
        new_user,
        read_secret,
    ):
        subparser = subparsers.add_parser(function.__name__, help=function.__doc__)
        subparser.set_defaults(method=function)
        for add_argument in getattr(function, "args", []):
            add_argument(subparser)
    args = parser.parse_args()
    if not getattr(args, "method", False):
        parser.error("Need to specify what function to use.")
    args.method(
        **{param: getattr(args, param) for param in signature(args.method).parameters}
    )


if __name__ == "__main__":
    main()
