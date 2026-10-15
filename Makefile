format:
	ruff format .
	ruff check --fix .
	djlint src/ftp_ids/dashboard/templates --reformat

format-check:
	ruff format --check .
	djlint src/ftp_ids/dashboard/templates --check

lint:
	ruff check .
	djlint src/ftp_ids/dashboard/templates --lint

test:
	pytest

.PHONY: format format-check lint test
