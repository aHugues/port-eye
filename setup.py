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
    python_requires=">=2.7",
    entry_points={"console_scripts": ["port-eye=port_eye.main:main"]},
       classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
)