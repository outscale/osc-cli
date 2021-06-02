# How to submit a contribution

Thank you for considering contributing to OSC-CLI.

Potential contributions include:

- Reporting and fixing bugs.
- Requesting features.
- Adding features.
- Cleaning up the code.
- Improving the documentation.

In order to report bugs or request features, search the issue tracker to check for a duplicate.

It’s totally acceptable to create an issue when you’re unsure whether
something is a bug or not. We’ll help you figure it out.

Use the same issue tracker to report problems with the documentation.

# Running tests

Pre-requisites:
- An Outscale account on eu-west-2 region
- At least 10 AccessKeys in your quota
- Have `softhsm`, `pkcs11-tool` and `openssl` installed on a Linux machine (smartcard tests)

Setup: edit `tests/config.env` and fill credentials.

Finally, you can run `make test`.

Warning: config files in `~/.osc/config.json` and `~/.osc_sdk/config.json` will be overwritten during tests.

# Pull Requests

We’ll do our best to review your pull request (or “PR” for short) quickly.

Each PR should, as much as possible, address just one issue and be self-contained.
Smaller the set of changes in the pull request is, the quicker it can be reviewed and
merged - if you have ten small, unrelated changes, then go ahead and submit ten PRs.
