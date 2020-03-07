from setuptools import setup


with open("README.md", "r") as fh:
    long_description = fh.read()


setup(
    name="sharedvault",
    version="1.0",
    author="Dorian Jaminais",
    author_email="sharedvault@jaminais.fr",
    description="SharedVault is a small application that allows you to define a "
    "secret that will require multiple people to unlock.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nanassito/sharedvault",
    py_modules=["sharedvault"],
    test_suite="test_all",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Public Domain",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=["cryptography", "sqlalchemy"],
)
