PYTHON ?= python3

.PHONY: fmt lint check

fmt:
	$(PYTHON) -m black src tests

lint:
	$(PYTHON) -m ruff check src tests

check: lint
	$(PYTHON) -m black src tests --check
	$(PYTHON) -m pytest -q
