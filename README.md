[![Project Graduated](https://docs.outscale.com/fr/userguide/_images/Project-Graduated-green.svg)](https://docs.outscale.com/en/userguide/Open-Source-Projects.html)

# Outscale CLI

Official Outscale CLI providing connectors to Outscale API.

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Maintenance mode !

This project is now in maintenance mode, we will still fix bugs here, but no new features will be work on.
If you want new features, you should use [oapi-cli](https://github.com/outscale/oapi-cli),
which support all of oapi-cli, and have some syntax suggar to ease complex argument manipulation in comparaison to osc-cli usage.

## Getting Started


### Installing on Macos

osc-cli is available on [brew](https://formulae.brew.sh/formula/osc-cli).

### Installing on Linux

osc-cli is pre-packaged for Linux as a standalone [AppImage](https://appimage.org/).
- Download `osc-cli-x86_64.AppImage` from latest version in [releases](https://github.com/outscale/osc-cli/releases).
- Allow file to be executed by running `chmod a+x osc-cli-x86_64.AppImage`
- Run osc-cli: `./osc-cli-x86_64.AppImage`

Optionally, you can install it for all users: `sudo mv osc-cli-x86_64.AppImage /usr/local/bin/osc-cli` and just run `osc-cli`.

you can also install `osc-cli-git` on Arch Linux using AUR: (`yay -S osc-cli-git`)

#### Note:

if you have this error (or one similar about fuse):
```
fuse: failed to exec fusermount: No such file or directory

Cannot mount AppImage, please check your FUSE setup.
You might still be able to extract the contents of this AppImage
if you run it with the --appimage-extract option.
See https://github.com/AppImage/AppImageKit/wiki/FUSE
for more information
open dir error: No such file or directory
```

You can either install fuse yourself, or execute the appimage with `--appimage-extract-and-run` option

Example:
```
./osc-cli-x86_64.AppImage --appimage-extract-and-run osc-cli api ReadImages --profile=my
```

using `appimage-extract-and-run` extract the content of the AppImage in a temporary directory and execute it,
this operation is a **lot** slower than using fuse, and the fuse solution should be use if posible.


### Installing on Windows

[Check dedicated documentation](windows-setup.md) regarding windows installation.

### Installing from Python package

#### Prerequisites

You will need [Python 3.6+](https://www.python.org/) or later. Earlier versions including Python 2 are not supported.

#### Pip

You can get the package from [pypi](https://pypi.org/project/osc-sdk/):
```
pip3 install osc-sdk
```

If you are using Microsoft Windows, see [how to setup osc-cli on Windows](windows-setup.md).

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

The CLI requires a configuration file in `~/.osc/config.json` The content must be a JSON whose contents look like this:
/!\ the old configuration path using `.osc_sdk` folder is **deprecated**. Please use the new one with `.osc`.
```json
{"default":
    {"access_key": "MYACCESSKEY",
     "secret_key": "MYSECRETKEY",
     "region": "eu-west-2"
    },
  "us":
    {"access_key": "MYACCESSKEY",
     "secret_key": "MYSECRETKEY",
     "host": "outscale.com",
     "https": true,
     "method": "POST",
     "region": "us-east-2"
    }
}
```
You can add several profiles for different regions or users.

Optional parameters can be applied to each profile :
* client_certificate: if you need additional security, your pem must include your private key and your certificate
* version: if you want to query another version of the API

```json
{"default":
    {"access_key": "MYACCESSKEY",
     "secret_key": "MYSECRETKEY",
     "client_certificate" : "path_to_your_pem",
     "host": "outscale.com",
     "https": true,
     "method": "POST",
     "region": "eu-west-2",
     "version": "2018-11-19"
    }
}
```

## Get osc-cli version

`--version` option will print osc-cli version and exit.
```
osc-cli --version
```

## Activate bash-completion

### Activate the completion for the current bash session

```
source <(osc-cli --bash_completion)
```

### Generate the file to add it in your bach rc:
```
osc-cli --bash_completion > ~/.osc/cli-completion.bash
```
then in your bashrc add:

```
source ~/.osc/cli-completion.bash
```

## Usage

```
osc-cli SERVICE CALL [PROFILE] [CALL-PARAMETERS]
```
or
```
osc-cli --service SERVICE --call CALL [PROFILE] [--CALL_PARAMS ...]
```
with
* SERVICE one of the [services](http://docs.outscale.com) provided by Outscale (`fcu`, `lbu`, `icu`, `eim`, `directlink`, `okms` and `api`)
* CALL the call you request (ie ReadVms, DescribeInstances...)
* PROFILE the profile you want to connect to (optional)
* CALL_PARAMS call arguments which are case-sensitive (optional)


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
$ osc-cli icu CreateAccount --Email "example@email.com" \
			    --FirstName "Osc" \
			    --LastName "Cli" \
			    --Password "12345toto" \
			    --ZipCode '"92000"' \
			    --Country "France" \
			    --CustomerId '"12345678"'
```

Another example with an array of strings into args:
```bash
$ osc-cli api CreateDhcpOptions --DomainName="toot.toot" \
				--DomainNameServers="['1.1.1.1']" \
				--NtpServers="['1.1.1.1']"
```

Example with a complex structure:
```bash
osc-cli icu CreateListenerRule \
--Instances '[{"InstanceId": "i-12345678"}]' \
--ListenerDescription '{"LoadBalancerName": "osc", "LoadBalancerPort": 80}'
--ListenerRuleDescription '{"RuleName": "hello", "Priority": 100, "PathPattern": "/"}'
```

**Argument Parsing**
```bash
$ osc-cli api example --obj=[1,2]    	# list
$ osc-cli api example --obj=10		# int
$ osc-cli api example --obj="10"	# int
$ osc-cli api example --obj="'10'"	# str
$ osc-cli api example --obj=\"10\"	# str

$ osc-cli api example --obj="hello"	# str
$ osc-cli api example --obj=hello	# str
```
**Warning** if you're adding a list which contain strings with specifics characteres, there is a workaround:
```bash
$ osc-cli api example --obj="['vol-12345678', 'vol-87654322']"    	# list
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
