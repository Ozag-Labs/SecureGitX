---
title: development
category: develop
order: 2
summary: Setting up a local development environment and running tests.
related: docs/develop/architecture,docs/default/rules-format
---

# development

## Setup

```sh
git clone https://github.com/Ozag-Labs/SecureGitX.git
cd SecureGitX
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Make targets

```sh
make install    # install with dev dependencies
make test       # run tests
make coverage   # tests with coverage report
make rules      # validate and list rules
```

## Running tests

```sh
make test
```

Tests live in `tests/`. The test suite uses `pytest`. Each scanner module has a corresponding test file.

Coverage report:

```sh
make coverage
# opens htmlcov/index.html
```

## Validating rules

```sh
make rules
# equivalent to: securegitx rules validate && securegitx rules list
```

Always run this after editing `rules.json` to confirm all patterns compile and no required fields are missing.

## Contributing

### Rules

1. Edit `src/securegitx/rules/rules.json`.
2. Run `make rules` to validate.
3. Include at least 2 `examples` and 2 `non_examples`.
4. Open a pull request. No real credentials in examples — use synthetic patterns.

See [Rules Format](/docs/default/rules-format) for the full schema.

### Code

- Keep modules separated by concern (see [Architecture](/docs/develop/architecture)).
- `scanner.py` must not call git. `gitops.py` must not contain rule logic.
- The hook path must remain synchronous and fast.
- New CLI commands go through `cli.py` dispatch — no scanning logic in the dispatcher.

## Local state (never committed)

```
.securegitx/
├── cache/
├── logs/
└── daemon.pid
```

This directory is added to `.gitignore` by `securegitx init` and should never appear in commits.