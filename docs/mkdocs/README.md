# Documentation Site

This is the MkDocs source for project guidance, research-process decisions, and dataset cards. Restore the canonical locked environment before serving the site:

```bash
uv sync --locked
uv run --locked python -m mkdocs serve --config-file docs/mkdocs/mkdocs.yml
```

Use `make docs` in CI or before publishing to build the site strictly. The documentation CI job installs only the exact `docs` group from `uv.lock`. Keep source Markdown under `docs/mkdocs/docs/`; generated output is ignored.
