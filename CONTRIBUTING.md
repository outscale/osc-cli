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

Setup:
- Fill a valid `default` profile in `~/.osc/config.json`
- `export OSC_TEST_LOGIN="your.login@mycompany.com"`
- `export OSC_TEST_PASSWORD="MySecretPassword"`
- `export OSC_TEST_ACCESS_KEY="ASJOAEHDIOEXAMPLE"`
- `export OSC_TEST_SECRET_KEY="ASJOAEHSDF4565D4F6D54F6D5F4F654DIOEXAMPLE"`

Warning: config files in `~/.osc/config.json` and `~/.osc_sdk/config.json` will be overwritten during tests. Make sure to backup them if needed.

Finally, you can run `make test`.

# Pull Requests

We’ll do our best to review your pull request (or “PR” for short) quickly.

Each PR should, as much as possible, address just one issue and be self-contained.
Smaller the set of changes in the pull request is, the quicker it can be reviewed and
merged - if you have ten small, unrelated changes, then go ahead and submit ten PRs.
