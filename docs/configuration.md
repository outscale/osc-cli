# Configuration

The CLI reads its configuration from `~/.osc/config.json`.

Legacy path `.osc_sdk` is deprecated; use `.osc`.

## Minimal example
```json
{
  "default": {
    "access_key": "MYACCESSKEY",
    "secret_key": "MYSECRETKEY",
    "region": "eu-west-2"
  }
}
```

## Multiple profiles
```json
{
  "default": {
    "access_key": "MYACCESSKEY",
    "secret_key": "MYSECRETKEY",
    "region": "eu-west-2"
  },
  "us": {
    "access_key": "MYACCESSKEY",
    "secret_key": "MYSECRETKEY",
    "host": "outscale.com",
    "https": true,
    "method": "POST",
    "region": "us-east-2"
  }
}
```

## Optional parameters
- `client_certificate`: path to a PEM that includes both private key and certificate
- `version`: target API version (e.g., `2018-11-19`)

Example:
```json
{
  "default": {
    "access_key": "MYACCESSKEY",
    "secret_key": "MYSECRETKEY",
    "client_certificate": "path_to_your_pem",
    "host": "outscale.com",
    "https": true,
    "method": "POST",
    "region": "eu-west-2",
    "version": "2018-11-19"
  }
}
```
