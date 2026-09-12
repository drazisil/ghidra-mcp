# ghidra-mcp

MCP server for Ghidra, built on [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra) and [FastMCP](https://github.com/jlowin/fastmcp). Opens a Ghidra project once at startup and keeps it open for the lifetime of the process — all tools share the same program handle with no per-call JVM startup cost.

Supports two transport modes:
- **stdio** — subprocess launched directly by an MCP client (Claude Code default)
- **streamable-http** — long-running HTTP server; multiple clients share one open project

## Requirements

- Ghidra 11+ (tested on 12.1.2)
- Python 3.11+
- [uv](https://docs.astral.sh/uv/)

## Setup

```sh
git clone https://github.com/drazisil/ghidra-mcp
cd ghidra-mcp
uv venv
uv sync
uv pip install "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg"
```

The `pyghidra` package is bundled with Ghidra, at a path that's different on every machine, so it's deliberately *not* a declared project dependency — it's installed imperatively via `uv pip install` (uv's pip-compatible interface, which installs into the venv without touching `pyproject.toml`/`uv.lock`) rather than `uv add`. This also installs `jpype1` automatically, since `pyghidra`'s own package metadata declares it.

**Important:** because `pyghidra` isn't in the lockfile, a plain `uv sync` will uninstall it again (it removes anything not declared). Use `uv sync --inexact` for any sync after the initial setup, or just re-run the `uv pip install` line above afterward.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | *(required, no default)* | Path to Ghidra installation, e.g. `/opt/ghidra_12.1.2_PUBLIC` |
| `GHIDRA_PROJECT_PATH` | current working directory | Directory containing the `.gpr` project file |
| `GHIDRA_PROJECT_NAME` | *(unset — startup project-open is optional)* | Project name to open at startup (no extension), e.g. `myproject` |
| `GHIDRA_PROGRAM_NAME` | *(unset — startup program-open is optional)* | Program filename to open at startup, e.g. `target.exe` |
| `MCP_TRANSPORT` | `stdio` | Transport: `stdio` or `streamable-http` |
| `MCP_HOST` | `127.0.0.1` | Bind host (streamable-http only) |
| `MCP_PORT` | `8765` | Bind port (streamable-http only) |

Ghidra holds a project lock when open. If the server starts while the project is locked by another process (e.g. the Ghidra GUI has it open), it will print a clear error and exit with code 3 — close the GUI (or the other process) first.

### Exposing the server behind a reverse proxy / custom domain

`streamable-http` mode has DNS-rebinding protection on by default whenever `MCP_HOST` is a loopback address, which validates both the `Host` and `Origin` headers against an allowlist (see `_mcp_transport_security` in `server.py`). If you're putting this behind a reverse proxy on a real domain (e.g. Caddy, for use as a claude.ai custom connector), you need both of the following or requests get rejected with 421/403 before ever reaching the tool logic:

- The proxy must rewrite the `Host` header to the loopback value the server expects (e.g. Caddy's `reverse_proxy { header_up Host localhost:<port> }`), since the allowlist only contains loopback patterns.
- The server's `allowed_hosts`/`allowed_origins` in `server.py` must include the real domain/origin (e.g. `https://claude.ai`) that will actually be hitting it — the proxy fixing up `Host` doesn't help `Origin`, which is checked independently and isn't touched by the header rewrite.

## Running

### stdio (direct MCP client launch)

The client launches the process; no server setup needed. Example Claude Code config (`~/.claude.json`):

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/ghidra-mcp/.venv/bin/python",
      "args": ["-m", "ghidra_mcp.server"],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra",
        "GHIDRA_PROJECT_PATH": "/path/to/project",
        "GHIDRA_PROJECT_NAME": "myproject",
        "GHIDRA_PROGRAM_NAME": "target.exe"
      }
    }
  }
}
```

### streamable-http (long-running server)

Start with `MCP_TRANSPORT=streamable-http`. The server listens at `http://<host>:<port>/mcp`.

#### systemd user service

```ini
# ~/.config/systemd/user/ghidra-mcp.service
[Unit]
Description=Ghidra MCP Server (SSE)
After=network.target

[Service]
Type=simple
WorkingDirectory=/path/to/ghidra-mcp
ExecStart=/path/to/ghidra-mcp/.venv/bin/python -m ghidra_mcp.server
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=3

Environment="MCP_TRANSPORT=streamable-http"
Environment="MCP_HOST=0.0.0.0"
Environment="MCP_PORT=8765"
Environment="GHIDRA_INSTALL_DIR=/path/to/ghidra"
Environment="GHIDRA_PROJECT_PATH=/path/to/project"
Environment="GHIDRA_PROJECT_NAME=myproject"
Environment="GHIDRA_PROGRAM_NAME=target.exe"

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now ghidra-mcp
```

#### Claude Code (http transport, pointing at running server)

```json
{
  "mcpServers": {
    "ghidra": {
      "type": "http",
      "url": "http://localhost:8765/mcp"
    }
  }
}
```

#### Hermes Agent or other MCP-over-HTTP clients

```yaml
mcp_servers:
  ghidra:
    url: http://host.docker.internal:8765/mcp
```

## Tools

### Read (always available)

| Tool | Description |
|---|---|
| `decompile_function` | Decompile a function to C. Pass name or hex address. |
| `list_functions` | List functions, optionally filtered by name substring. |
| `get_function_instructions` | List all instructions in a function with address, mnemonic, and flow type. |
| `get_function_calls` | Return all direct callees of a function. |
| `get_references_to` | Return all XREFs to an address. |
| `get_struct` | Return struct layout: offsets, field types, sizes. |
| `list_structs` | List all struct data types, optionally filtered. |
| `dump_bytes` | Hex dump a memory range with per-byte classification (INSTR/DATA/UNDEF). |
| `find_symbol` | Find address(es) for a label/symbol by name substring (reverse of address->name lookup). |
| `switch_active_program` | Switch the active program (must already be in the project). |

### Write

| Tool | Description |
|---|---|
| `rename_function` | Rename a function by address. |
| `set_function_comment` | Set the plate comment on a function. |
| `create_function` | Define a new function at an address Ghidra hasn't already recognized as one (disassembles first if needed; body auto-determined by following control flow, same as the GUI's "Create Function" action). |
| `create_struct` | Create a new empty struct data type. |
| `apply_struct_member` | Place a field into a struct at a given byte offset. |
| `fix_vc6_call_terminators` | Fix VC6 debug build `CALL_TERMINATOR` / `__chkesp` problem across all call sites (two-pass). |
| `extend_function_body` | Extend a single function body past a `CALL_TERMINATOR`. |
| `redisassemble_instruction` | Clear and re-disassemble one instruction to recompute FlowType. |

Addresses are 32-bit hex strings: `'0055e190'`, not `0x0055e190`.
