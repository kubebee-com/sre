# Historical standalone compatibility tests

This internal package retains the old standalone regression fixtures during the
migration. Neither sre-agent nor sre-orchestrator imports it. Its HTTP/CLI entry
path is unexported and unavailable from the product binaries. Shared provider,
scanner and action libraries remain the implementations used by maintained code.
