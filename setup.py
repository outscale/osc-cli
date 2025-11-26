import os

from setuptools import find_packages, setup


def get_long_description():
    root_path = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(root_path, "README.md"), "r", encoding="utf-8") as fd:
        return fd.read()


setup(
    name="osc-sdk",
    version="1.11.0",
    packages=find_packages(),
    author="Outscale SAS",
    author_email="contact@outscale.com",
    description="Outscale API SDK and CLI",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    include_package_data=True,
    license="BSD",
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    url="https://github.com/outscale/osc-cli",
    entry_points={"console_scripts": ["osc-cli = osc_sdk.sdk:main"]},
    install_requires=[
        "setuptools",
        'dataclasses>=0.8; python_version < "3.7"',
        "defusedxml>=0.7.1",
        "fire>=0.1.3",
        "requests>=2.26.0",
        "typing_extensions>=3.10.0.2",
        "xmltodict>=0.11.0",
    ],
)
