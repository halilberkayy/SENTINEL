# Contributing to SENTINEL

Thanks for your interest in improving SENTINEL. This guide covers local setup,
the quality gates, and how to add a scanning module.

## Development setup

```bash
# Clone and install (Poetry is the source of truth for dependencies)
git clone https://github.com/halilberkayy/SENTINEL.git
cd SENTINEL
poetry install

# Install pre-commit hooks (black, isort, ruff, mypy, bandit, secret scanners)
poetry run pre-commit install
```

Python 3.10, 3.11, and 3.12 are supported.

## Quality gates

Run everything the way CI does before opening a PR:

```bash
make lint        # ruff + black + mypy
make test-unit   # pytest (unit)
make security    # bandit + safety
```

Or individually:

```bash
poetry run ruff check src tests      # enforced in CI
poetry run black --check src tests   # enforced in CI
poetry run mypy src                  # advisory (gradual typing)
poetry run pytest tests/unit/        # enforced in CI
```

**Enforced gates:** `ruff` and `black` must pass, and unit tests must stay green
with coverage at or above the configured threshold. `mypy` and `bandit` are
advisory today; new code should still aim to type-check cleanly.

## Adding a scanning module

1. Create `src/modules/<name>_scanner.py`.
2. Subclass `BaseScanner` and implement `async def scan(self, url, progress_callback=None)`.
3. Register it in `MODULE_REGISTRY` in `src/core/scanner_engine.py`:
   ```python
   "my_scanner": ("src.modules.my_scanner", "MyScanner"),
   ```
4. Add a unit test under `tests/unit/`.
5. Return findings through `_create_vulnerability`. Set `severity` yourself.
   The CVSS table fills a score. It does not override that severity.
   Put the URL, status, and the header or path you actually observed in `evidence`.

## Commit and PR conventions

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`,
  `docs:`, `refactor:`, `test:`, `chore:`.
- Keep PRs focused; one logical change per PR.
- Describe what changed, why, and how you verified it.
- Never commit secrets, `.env` files, or scan results against real targets.

## Responsible disclosure

Found a vulnerability in SENTINEL itself? Do not open a public issue.
Follow [`SECURITY.md`](SECURITY.md).
