"""Cli too to manipulate a shared vault.
"""

from argparse import ArgumentParser
from pathlib import Path
from sharedvault.vault import FileVault


def home()
    while action:= input()


def main(path: Path) -> None:
    with FileVault(path).open() as vault:
        home()


if __name__ == "__main__":
    parser = ArgumentParser(__doc__)
    parser.add_argument("path", type=Path, help="path of the vault.")
    args = parser.parse_args()
    main(args.path)
