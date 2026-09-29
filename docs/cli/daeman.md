---
title: daeman
category: cli
order: 5
summary: An optional background process that watches git index for changes.
related: docs/cli/init,docs/develop/architecture
---

# daeman

An optional background process that watches git index for changes.

The daemon is **off by default**. It must be declared to run.

## Commands

```sh
securegitx daeman start   # start the watcher
securegitx daeman stop    # stop the running daeman
securegitx daeman status  # show status
```
