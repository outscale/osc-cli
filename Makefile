all: help

.PHONY: help
help:
	@echo "Available targets:"
	@echo "- build: python package building"
	@echo "- package: package osc-cli for various platforms"
	@echo "- test: run all tests"
	@echo "- test-pre-commit: run pre-commit tests"
	@echo "- test-pylint: check code with pylint"
	@echo "- test-bandit: security check with bandit"
	@echo "- test-mypy: run typing tests"
	@echo "- test-int: run integration tests"
	@echo "- clean: clean temp files, venv, etc"

.PHONY: package
package:
	cd pkg && make

.PHONY: test
test: clean test-pre-commit test-pylint test-bandit test-mypy test-int build
	@echo "All tests OK"

.PHONY: test-pre-commit
test-pre-commit:
	pre-commit run --all-files

.PHONY: test-pylint
test-pylint: .venv/ok
	@./tests/test_pylint.sh

.PHONY: test-bandit
test-bandit: .venv/ok
	@./tests/test_bandit.sh

.PHONY: test-mypy
test-mypy:
	./tests/test_mypy.sh

.PHONY: test-int
test-int: .venv/ok
	./tests/test_int.sh

.PHONY: build
build: .venv/ok
	@./tests/build.sh

.venv/ok:
	@./tests/setup_venv.sh

.PHONY: clean
clean:
	rm -rf .venv osc_sdk.egg-info dist
