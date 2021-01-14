from setuptools import find_packages, setup

setup(
    name="osc-sdk",
    version="1.6",
    packages=find_packages(),
    author="Outscale SAS",
    author_email="contact@outscale.com",
    description="Outscale",
    url="http://www.outscale.com/",
    entry_points={"console_scripts": ["osc-cli = osc_sdk.sdk:main"]},
    install_requires=[
        "setuptools",
        "fire==0.1.3",
        "requests==2.21.0",
        "xmltodict==0.11.0",
    ],
)
