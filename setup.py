#!/usr/bin/env python

from setuptools import setup, find_namespace_packages

setup(
    name="proton-core",
    version="0.1.14",
    description="Proton Technologies API wrapper",
    author="Proton Technologies",
    author_email="contact@protonmail.com",
    url="https://github.com/ProtonMail/python-proton-core",
    install_requires=["requests", "bcrypt", "python-gnupg", "pyopenssl", "aiohttp"],
    extras_require={
        "test": ["pytest", "pyotp", "pytest-cov", "flake8"]
    },
    entry_points={
        "proton_loader_keyring": [
            "json = proton.keyring.textfile:KeyringBackendJsonFiles"
        ],
        "proton_loader_transport": [
            "requests = proton.session.transports.requests:RequestsTransport",
            "alternativerouting = proton.session.transports.alternativerouting:AlternativeRoutingTransport",
            "aiohttp = proton.session.transports.aiohttp:AiohttpTransport",
            "auto = proton.session.transports.auto:AutoTransport",
        ],
        "proton_loader_environment": [
            "prod = proton.session.environments:ProdEnvironment",
        ],
        "proton_loader_basicview": [
            "cli = proton.views.basiccli:BasicCLIView"
        ]
    },
    packages=find_namespace_packages(include=['proton.*']),
    include_package_data=True,
    python_requires=">=3.8",
    license="GPLv3",
    platforms="OS Independent",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Topic :: Security",
    ]
)
