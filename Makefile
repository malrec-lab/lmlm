UV ?= uv

.PHONY: help sync lock lock-check test lint format-check format docs check

help:
	@printf '%s\n' \
	  'make sync         - create/update .venv from the committed lock' \
	  'make lock         - resolve dependencies and update uv.lock' \
	  'make lock-check   - verify pyproject.toml and uv.lock agree' \
	  'make test         - run the test suite from the locked environment' \
	  'make lint         - lint source and tests' \
	  'make format-check - verify source and test formatting' \
	  'make format       - fix lint and formatting issues' \
	  'make docs         - build MkDocs documentation strictly' \
	  'make check        - run all non-mutating repository checks'

sync:
	$(UV) sync --locked

lock:
	$(UV) lock

lock-check:
	$(UV) lock --check

test:
	$(UV) run --locked pytest -v

lint:
	$(UV) run --locked ruff check malweave tests

format-check:
	$(UV) run --locked ruff format --check malweave tests

format:
	$(UV) run --locked ruff check --fix malweave tests
	$(UV) run --locked ruff format malweave tests

docs:
	$(UV) run --locked python -m mkdocs build --strict --config-file docs/mkdocs/mkdocs.yml

check: lock-check lint format-check test docs
