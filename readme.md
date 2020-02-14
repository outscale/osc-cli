# Outscale CLI

Official Outscale CLI providing connectors to Outscale API.

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Getting Started

### Prerequisites

You will need [Python 3.5+](https://www.python.org/) or later. Earlier versions including Python 2 are not supported.

### Installing from package

You can get the .whl file from releases and install it through:
```
pip3 install osc_sdk-1.1-py3-none-any.whl
```

### Installing from sources

It is a good practice to create a [dedicated virtualenv](https://virtualenv.pypa.io/en/latest/) first. Even if it usually won't harm to install Python libraries directly on the system, better to contain dependencies in a virtual environment.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Then install osc-cli in your virtual env:
```bash
pip install -e .
```

## Configure osc-cli

The CLI requires a configuration file in `~/.osc_sdk/config.json` The content must be a JSON whose contents look like this:
```json
{"default":
    {"access_key": "MYACCESSKEY",
     "secret_key": "MYSECRETKEY",
     "host": "outscale.com",
     "https": true,
     "method": "POST",
     "region_name": "eu-west-2",
     "version": "2018-11-19"
    }
}
```
You can add several profiles for different regions or users.

## Usage

```
osc-cli SERVICE CALL [PROFILE] [CALL-PARAMETERS]
```
or
```
osc-cli --service SERVICE --call CALL [PROFILE] [--CALL_PARAMS ...]
```
with 
* SERVICE one of the services provided by Outscale (api, fcu, lbu, eim, directconnect, icu)
* CALL the call you request (ie ReadVms, DescribeInstances...)
* PROFILE the profile you want to connect to (optional)
* CALL_PARAMS call arguments which are case-sensitive (optional)

You can find the `fcu`, `lbu`, `icu`, `eim`, `directlink`, `okms` and `api` descriptions on [docs.outscale.com](http://docs.outscale.com).


Here is an example of a simple volume creation:
```bash
osc-cli fcu CreateVolume --AvailabilityZone eu-west-2a --Size 10
{
    "CreateVolumeResponse": {
        "@xmlns": "http://ec2.amazonaws.com/doc/2014-06-15/",
        "requestId": "508f428a-9fd8-4a49-9fe6-d0bf311de3b4",
        "volumeId": "vol-6a2aa442",
        "size": "10",
        "snapshotId": null,
        "availabilityZone": "eu-west-2a",
        "status": "creating",
        "createTime": "2019-01-17T12:53:57.836Z",
        "volumeType": "standard"
    }
}
```

Be careful with your quotes ! If you want to pass the string `"12345678"` rather than the integer `12345678` you'll need to quote your quotes:
```bash
$ osc-cli icu CreateAccount --Email "example@email.com" 
			    --FirstName "Osc" 
			    --LastName "Cli" 
			    --Password "12345toto" 
			    --ZipCode '"92000"' 
			    --Country "France"
			    --CustomerId '"12345678"'
```

## Authentication

You API crendentials are composed of an Access Key and a Secret Key located in `.osc_sdk/config.json`.
You can list you access keys using your user and password:
```bash
osc-cli icu ListAccessKeys --authentication-method=password --login youremail@company.com --password=Y0URpAssOrd
```
## Contributing
OSC-CLI is an **open source software** licensed under **BSD-3-Clause.**

Patches and discussions are welcome about bugs you've found or features you think are missing. If you would like to help making **osc-cli** better, take a look to [CONTRIBUTING.md](https://github.com/outscale/osc-cli/blob/master/CONTRIBUTING.md) file.
