import sys
from setuptools import find_packages, setup

# Solve compatibility issue with Python 2
if sys.version_info[0] == 2:
    from os import path
    with open(path.join(".", "README.md"), "r") as f:
        README = f.read().decode("string_escape")

else:
    from pathlib import Path
    with open(str(Path(".") / "README.md"), "r", encoding="utf-8") as f:
        README = f.read()

# Add version specific install packages
if sys.version_info[0] == 2:
    version_specific_packages = [
        "ipaddress>=1.0"
    ]
else:
    version_specific_packages = []

setup(
    name="port-eye",
    version="0.2.1",
    license="MIT",
    url="https://github.com/aHugues/port-eye.git",
    description="Simple CLI port scanner",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Aurélien Hugues",
    author_email="me@aurelienhugues.com",
    packages=find_packages(exclude=["tests*"]),
    include_package_data=True,
    install_requires=version_specific_packages+[
        "click>=7",
        "python-nmap>=0.6",
        "jinja2>=2.10",
        "blessings>=0.7",
        "pyfiglet>=0.8",
    ],
    extras_require={
        "dev": [
            "pytest",
            "pytest-cov",
            "codecov",
            "black",
            "pylint"
        ],
        "test": [
            "pytest",
            "pytest-cov",
            "codecov",
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
