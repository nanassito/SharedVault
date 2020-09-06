from configparser import ConfigParser
from datetime import date

import requests
from setuptools import setup
from urllib_ext.parse import urlparse


with open("README.md", "r") as fd:
    long_description = fd.read()


def get_dependencies():
    pipfile = ConfigParser()
    assert pipfile.read("Pipfile"), "Could not read Pipfile"
    return list(pipfile["packages"])


def get_next_version(project: str):
    project_url = urlparse("https://pypi.org/project") / project
    today = date.today()
    version = f"{today:%Y}.{today:%m}.{today:%d}"
    minor = 0
    while requests.get(str(project_url / version)).status_code == 200:
        minor += 1
        version = f"{today:%Y}.{today:%m}.{today:%d}.{minor}"
    return version


setup(
    name="sharedvault",
    version=get_next_version("sharedvault"),
    author="Dorian Jaminais",
    author_email="sharedvault@jaminais.fr",
    description="SharedVault is a small application that allows you to define a "
    "secret that will require multiple people to unlock.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nanassito/sharedvault",
    packages=["sharedvault"],
    test_suite="test_all",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Public Domain",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=get_dependencies(),
)
