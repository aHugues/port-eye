from setuptools import find_packages, setup
from pathlib import Path

with open(str(Path(".") / "README.md"), "r", encoding="utf-8") as f:
    README = f.read()

setup(
    name="port-eye",
    version="0.0",
    license="MIT",
    url="https://github.com/aHugues/port-eye.git",
    description="Simple CLI port scanner",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Aurélien Hugues",
    author_email="me@aurelienhugues.com",
    packages=find_packages(exclude=["tests*"]),
    extras_require={
        "dev": [
            "pytest",
            "pytest-cov",
            "codecov",
            "black",
            "pylint",
        ]
    },
    entry_points={"console_scripts": ["port-eye=port_eye.main:main"]},
)