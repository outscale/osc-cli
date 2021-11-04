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
- An Outscale account
- At least 50 AccessKeys in your quota
- [pre-commit](https://github.com/pre-commit/pre-commit-hooks) installed

Setup:
- Fill a valid `default` profile in `~/.osc/config.json`
- `export OSC_TEST_LOGIN="your.login@mycompany.com"`
- `export OSC_TEST_PASSWORD="MySecretPassword"`

Finally, you can run `make test`

# Pull Requests

We’ll do our best to review your pull request (or “PR” for short) quickly.

Each PR should, as much as possible, address just one issue and be self-contained.
Smaller the set of changes in the pull request is, the quicker it can be reviewed and
merged - if you have ten small, unrelated changes, then go ahead and submit ten PRs.

# How to release

- Be sure to be rebased on `master` branch
- Edit `osc_sdk/sdk.py` and update `SDK_VERSION` following [semantic versioning 2.0.0](https://semver.org/)
- Update `setup.py` to update `version`
- Run all tests with `make test`
- Build with `make build`. Make sure you have`dist/osc_sdk-1.x-py2.py3-none-any.whl` and `dist/osc-sdk-1.x.tar.gz`.
- Package with `make package`. Make sure you have `pkg/osc-cli-x86_64.zip` and `pkg/osc-cli-x86_64.AppImage` (you will need either docker or packman).
- Commit release update: `git commit -am "osc-cli v1.x.x"`
- Tag new release `git tag v1.x.x`
- Push release to new branch `git push --tags outscale master:v1.x.x`
- Create PR to run github actions and get validation
- Make the PR reviewed
- Create release page
- Add major change to release page
- Upload artifacts in release page:
  - `osc_sdk-1.x-py2.py3-none-any.whl`
  - `osc-sdk-1.x.tar.gz`
  - `osc-cli-x86_64.zip`
  - `osc-cli-x86_64.AppImage`
- Check that auto-build workflow has published package to pip
- Update homebrew:
  - Update [osc-cli's brew formula](https://github.com/Homebrew/homebrew-core/blob/master/Formula/osc-cli.rb#L6)
  - Update dependencies with `brew update-python-resources osc-cli`
  - Create PR and follow asked instructions in template
