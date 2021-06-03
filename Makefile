all: help

.PHONY: help
help:
	@echo "Available targets:"
	@echo "- build: python package building"
	@echo "- test: run all tests"
	@echo "- test-pylint: check code with pylint"
	@echo "- test-bandit: security check with bandit"
	@echo "- test-int: run integration tests"
	@echo "- setup-ubuntu-20.04: install needed tools to build and test on Ubuntu Linux"
	@echo "- clean: clean temp files, venv, etc"

.PHONY: test
test: clean test-pylint test-bandit test-int build
	@echo "All tests OK"

.PHONY: test-pylint
test-pylint: .venv/ok
	@./tests/test_pylint.sh

.PHONY: test-bandit
test-bandit: .venv/ok
	@./tests/test_bandit.sh

.PHONY: test-int
test-int: .venv/ok
	./tests/test_int.sh

.PHONY: build
build: .venv/ok
	@./tests/build.sh

.PHONY: setup-ubuntu-20.04
setup-ubuntu-20.04:
	@./tests/setup_ubuntu-20.04.sh

.venv/ok:
	@./tests/setup_venv.sh

.PHONY: clean
clean:
	rm -rf .venv osc_sdk.egg-info dist
