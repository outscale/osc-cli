[![Project Graduated](https://docs.outscale.com/fr/userguide/_images/Project-Graduated-green.svg)](https://docs.outscale.com/en/userguide/Open-Source-Projects.html)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![](https://dcbadge.limes.pink/api/server/HUVtY5gT6s?style=flat&theme=default-inverted)](https://discord.gg/HUVtY5gT6s)

<p align="center">
  <img alt="Terminal Icon" src="https://img.icons8.com/ios-filled/100/console.png" width="100px">
</p>

# Outscale CLI (osc-cli)

Official command-line interface for the OUTSCALE API.

> **Maintenance mode**: bug fixes only; no new features.  
> Looking for new features and an improved UX? See **[oapi-cli](https://github.com/outscale/oapi-cli)**.

## Quick start

**macOS (Homebrew)**
```bash
brew install osc-cli
````

**Linux (AppImage)**

```bash
# get the latest release from GitHub
chmod a+x osc-cli-x86_64.AppImage
./osc-cli-x86_64.AppImage
# (optional) sudo mv osc-cli-x86_64.AppImage /usr/local/bin/osc-cli
```

**Python package**

```bash
pip3 install osc-sdk
```

**Windows**
See [docs/install/windows.md](docs/install/windows.md).

## Minimal configuration

Create `~/.osc/config.json`:

```json
{
  "default": {
    "access_key": "MYACCESSKEY",
    "secret_key": "MYSECRETKEY",
    "region": "eu-west-2"
  }
}
```

## Usage

```bash
osc-cli SERVICE CALL [PROFILE] [CALL-PARAMETERS]
# example:
osc-cli api ReadVms
```

## Documentation

* Installation guides (macOS, Linux/AppImage, Windows, pip, source): [docs/install/](docs/install/)
* Configuration and profiles: [docs/configuration.md](docs/configuration.md)
* Usage and argument parsing: [docs/usage.md](docs/usage.md), [docs/argument-parsing.md](docs/argument-parsing.md)
* Shell completion: [docs/completion.md](docs/completion.md)
* Troubleshooting & FAQ: [docs/troubleshooting.md](docs/troubleshooting.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

BSD-3-Clause. See [LICENSE](LICENSE).