# Official Outscale SDK/CLI

Official SDK/CLI providing connectors to Outscale API.

## Getting Started

### Prerequisites

Python 3.5+ compatible. Earlier versions including Python 2 are not supported.

It is a good practice to create a dedicated virtualenv first. Even if it usually won't harm to install 
Python libraries directly on the system, better to contain dependencies in a virtual environment.

### Installing

If you have access to the Gitlab repository (usually devs and Outscale internal users), 
clone it and after navigating to the root folder, type:

```
pip install . -e
```
This would install the CLI from the sources.

If you have been provided with the .whl file, type:
```
pip install official_osc_sdk-0.1-py3-none-any.whl
```

## Using the CLI

The CLI requires a configuration file in ~/.osc_sdk/config.conf The content must be a JSON whose contents
look like this:
```
{"default":
    {"access_key": "",
     "host": "outscale.com",
     "https": true,
     "method": "POST",
     "region_name": "eu-west-2",
     "secret_key": "",
     "version": "2018-11-19"
    }
}
```
You can add several profiles for different regions or users.

You can access the CLI with:
```
osc-cli SERVICE CALL [PROFILE] [--KWARGS ...]
```
or
```
osc-cli --service SERVICE --call CALL [PROFILE] [--KWARGS ...]
```
with 
* SERVICE one of the services provided by Outscale (fcu, lbu, eim, directconnect, icu)
* CALL the call you request (ie DescribeInstances)
* PROFILE the profile you want to connect to (optional)
* KWARGS the arguments you need for your call (optional)

