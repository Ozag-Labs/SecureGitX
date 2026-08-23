![Diagram](assets/SecureGitX.png)

<div align="center">

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![CI](https://github.com/Ozag-Labs/SecureGitX/actions/workflows/ci.yml/badge.svg)](https://github.com/Ozag-Labs/SecureGitX/actions)

</div>

---

SecureGitX is a local first pre-commit secret scanner that blocks API keys, tokens, credentials, or sensitive filenames before they get committed.

---

## Install

```sh
pip install git+https://github.com/Ozag-Labs/SecureGitX.git
```

## One Liner 

```sh
curl -fsSL https://raw.githubusercontent.com/Ozag-Labs/SecureGitX/main/scripts/install.sh | bash
```

Or clone and install locally:

```sh
git clone https://github.com/Ozag-Labs/SecureGitX.git
cd SecureGitX
pip install -e ".[dev]"
```

Requires Python 3.10+.

---

## Quick start

```sh
#  Initialize your repo
securegitx init
securegitx hook install
```

If a secret is found, the commit is blocked with details on what was detected and how to fix it.

---

![Sample output](assets/demo.png)

---

## How it works

```
git commit → pre-commit hook → scan filenames + diff + entropy
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
              findings found?                 no findings
                    │                             │
                    ▼                             ▼
              commit blocked              commit proceeds
```

## Detects

20+ rules covering: AWS, GitHub, Stripe, Google OAuth, JWTs, Slack tokens, Firebase keys, PEM headers, database URLs, SSH keys, .env files, and more.