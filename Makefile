all: help

.PHONY: help
help:
	@echo "Available targets:"
	@echo "- test: run few basic tests"
	@echo "- clean: clean temp files (like .venv folder)"

.PHONY: test
test: .venv/ok
	( \
	. .venv/bin/activate && \
	pylint --rcfile=pylint_py3.conf osc_sdk && \
	bandit -c bandit.conf -r osc_sdk )

.venv/ok:
	( \
	rm -rf .venv && \
	python3 -m virtualenv .venv && \
	. .venv/bin/activate && \
	pip install -r requirements.txt && \
	touch $@ )

.PHONY: clean
clean:
	rm -rf .venv
