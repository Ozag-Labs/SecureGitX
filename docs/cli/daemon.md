---
title: daemon
category: cli
order: 5
summary: Optional background watcher that monitors the git index and queues .gitignore suggestions.
related: docs/cli/init,docs/develop/architecture
---

# daemon

An optional background process that watches git index for staging changes.

The daemon is **off by default**. It must be declared to run.

## Commands

```sh
securegitx daemon start   # start the watcher (runs in background)
securegitx daemon stop    # stop the running daemon
securegitx daemon status  # show status and last scan result
```
