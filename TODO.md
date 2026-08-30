# TODO

- **Find address by label** — add a tool to look up an address given a label/symbol name (reverse of the usual address→name lookup). No such tool exists yet.
- **MCP unreachable during restart boot window** — confirmed live 2026-08-30: after `systemctl --user restart ghidra-mcp.service`, the port (8765) doesn't accept connections for ~30s while pyghidra's JVM boots; any tool call in that window fails outright ("Unable to connect"). Once the port opens, calls succeed immediately — client reconnect itself is fine, there's just no retry/backoff for the boot window. Consider a startup health-check gate or client-side retry-with-backoff so callers don't have to guess when it's ready.
