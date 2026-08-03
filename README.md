# IDA Pro MCP — Headless Pool Fork

[中文版](README_zh.md) | English

MCP integration for IDA Pro and idalib. This fork of
[mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) focuses on a
headless, multi-session pool while retaining the IDA GUI plugin.

## Runtime modes

The installed commands have distinct roles:

| Command | Role |
|---|---|
| `idalib-pool` | Primary headless MCP server. Manages multiple IDBs and idalib backend processes. |
| `ida-pro-mcp` | Installs/configures the GUI plugin and, in stdio mode, proxies MCP requests to the plugin's local server. |
| `ida-mcp-test` | Runs the IDA-facing test suite with idalib. |

There is no public `idalib-mcp` command. `ida_pro_mcp.idalib_server` is an
internal, single-IDB backend spawned by `idalib-pool`.

## Architecture

```text
                               explicit session_id
MCP client ── stdio/HTTP/SSE ───────────┐
                                        ▼
                            ┌────────────────────────┐
                            │ idalib-pool            │
                            │ context/session router │
                            └───────┬────────┬───────┘
                                    │        │
                     inherited RPC/control  │ WebSocket /pool/ws
                              Pipes         │
                                    │        │
                              ┌─────▼───┐ ┌──▼──────────────┐
                              │ idalib  │ │ IDA GUI plugin  │
                              │ backend │ │ open IDB        │
                              └─────────┘ └─────────────────┘
```

The pool process does not import `idapro`. It discovers tool schemas with a
short-lived internal backend that is stopped immediately after discovery.
Every newly created local session starts its own dedicated backend process; the
pool does not keep idle backends for reuse. An IDA GUI plugin can instead
register its currently open IDB as an externally managed session.

Local backends are started with Python's cross-platform `spawn` context. RPC
and cancellation/shutdown use separate inherited `multiprocessing` pipes, so
the internal channel exposes no TCP port, Unix-socket path, or public named
pipe. The same lifecycle is used on Windows, Linux, and macOS.

### Session behavior

- One local session owns one idalib backend process and one active IDB.
- Creating a local session always starts a new backend. Closing its last
  reference saves the IDB and terminates that backend.
- `idalib_open` binds the returned session to the caller's MCP transport
  context. Streamable HTTP sessions and SSE connections therefore keep
  independent default routing; stdio has one context.
- An explicit `session_id` on an IDA tool overrides the context binding.
- Reopening the same binary or IDB shares the existing session by default and
  increments its reference count for the new caller.
- `idalib_switch` changes only the caller's context binding. It does not change
  ownership or reference counts.
- `idalib_close` releases one reference. When the count reaches zero, a local
  IDB is saved and its backend process is stopped.
- Pool-owned session IDs are derived from the file name plus a stable path
  digest; callers must use the ID returned by `idalib_open`.
- There is no LRU eviction and no global default session.

## Prerequisites

- [Python](https://www.python.org/downloads/) 3.11+
- [IDA Pro](https://hex-rays.com/ida-pro) 8.3+ with
  [idalib](https://docs.hex-rays.com/user-guide/idalib) (IDA 9.x recommended)
- A licensed IDA Pro installation; IDA Free does not support this plugin
- `IDADIR` set to the IDA installation directory when it cannot be discovered
  automatically

Example:

```sh
export IDADIR=/path/to/ida-pro
```

PowerShell:

```powershell
$env:IDADIR = "C:\Program Files\IDA Professional 9.1"
```

## Installation

From the current repository:

```sh
git clone https://github.com/winmin/ida-headless-mcp.git
cd ida-headless-mcp
uv sync
```

Or install the current `main` branch with pip:

```sh
pip install https://github.com/winmin/ida-headless-mcp/archive/refs/heads/main.zip
```

## Headless pool

### Start the server

```sh
# stdio, suitable for a client-managed local process
uv run idalib-pool

# Streamable HTTP at /mcp and legacy SSE at /sse
uv run idalib-pool --transport http://127.0.0.1:8750

# Explicit IDA location; overrides IDADIR for this pool process
uv run idalib-pool --ida-dir "/path/to/ida-pro" \
  --transport http://127.0.0.1:8750

# Require a bearer token on HTTP, SSE, and GUI pool WebSocket requests
uv run idalib-pool \
  --transport http://127.0.0.1:8750 \
  --auth-token "replace-with-a-secret"

# Disable tools marked unsafe; unsafe tools are enabled by default
uv run idalib-pool --safe

# Use a specific directory for backend logs
uv run idalib-pool --runtime-dir ./ida-mcp-runtime
```

`--ida-dir` has priority over `IDADIR`. If the option is omitted, the existing
environment-variable and idapro configuration-file discovery continue to work.
On PowerShell, quote paths containing spaces, for example
`--ida-dir "C:\Program Files\IDA Professional 9.1"`.

`IDA_MCP_AUTH_TOKEN` is equivalent to `--auth-token`.

Open binaries and IDBs through `idalib_open` after the MCP client connects.
This ensures every created session has an owning reference and transport
context.

### Large tool results

In HTTP/SSE pool mode, oversized results contain a preview plus an
`_download_url` served by the pool itself. The URL returns the complete JSON
result and requires the same bearer token when authentication is enabled.
In stdio mode there is no HTTP download endpoint, so the pool returns the
complete structured result inline instead of emitting an unusable URL.

Download entries are memory-backed and bounded to the latest 100 results;
they are lost when the serving process restarts. Download important output
before opening enough newer large results to evict it.

### MCP client configuration

Local stdio configuration:

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "idalib-pool"
    }
  }
}
```

Streamable HTTP configuration:

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "url": "http://127.0.0.1:8750/mcp"
    }
  }
}
```

From a source checkout:

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/ida-headless-mcp",
        "idalib-pool"
      ]
    }
  }
}
```

### Typical workflow

```text
idalib_open(input_path="/firmware/httpd")
  -> session_id="httpd_a1b2c3"; caller context is now bound to it

idalib_open(input_path="/firmware/libcrypto.so")
  -> session_id="libcrypto_d4e5f6"; caller context moves to it

decompile(addr="SSL_connect")
  -> routed through the caller's current context binding

decompile(addr="main", session_id="httpd_a1b2c3")
  -> explicit routing, without changing the context binding

idalib_close(session_id="httpd_a1b2c3")
idalib_close(session_id="libcrypto_d4e5f6")
  -> release every session opened by this caller
```

Balance every successful `idalib_open` with `idalib_close`. Use
`idalib_close(force=true)` only for administrative recovery: it bypasses
reference counts and disconnects all contexts from the session.

### Pool management tools

| Tool | Behavior |
|---|---|
| `idalib_open(input_path, ...)` | Open or share a binary/IDB, bind it to the caller, and return the pool-owned session ID. |
| `idalib_close(session_id?, force?)` | Release a reference; save and close a local session at refcount zero. |
| `idalib_switch(session_id)` | Change the caller's context binding without changing refcounts. |
| `idalib_list()` | List sessions, refcounts, ownership type, and the caller's current binding. |
| `idalib_current()` | Return the session bound to the caller's context. |
| `idalib_save(path?, session_id?)` | Save without closing. |
| `idalib_health(session_id?)` | Query backend/plugin readiness. |
| `idalib_warmup(session_id?, ...)` | Warm auto-analysis, caches, and Hex-Rays. |

All regular IDA tools exposed by the backend receive an optional `session_id`
in pool mode. Available tools are discovered at runtime rather than maintained
as a fixed count in this README.

## IDA GUI plugin

Install the plugin and optionally configure supported MCP clients:

```sh
# Interactive client/transport/scope selection
uv run ida-pro-mcp --install

# Non-interactive example
uv run ida-pro-mcp --install claude-code --transport streamable-http --scope global

# Inspect supported client targets or print generic configuration
uv run ida-pro-mcp --list-clients
uv run ida-pro-mcp --config
```

Restart IDA after the first installation.

### Local GUI server

Open an IDB in IDA, then choose **MCP > Run Local MCP Server**. The default
address is `127.0.0.1:13337`; **MCP > Configuration** changes the host and port
using an IDA-native dialog. There is no browser configuration page.

With Streamable HTTP/SSE client installation, the client connects directly to
the plugin server. With stdio installation, the client launches
`ida-pro-mcp`, which proxies requests to that local server. Local-server mode
and pool-connection mode are mutually exclusive.

### Register a GUI IDB in the pool

Start `idalib-pool` with an HTTP transport, then in IDA choose
**MCP > Connect to Pool** and enter the pool URL (for example,
`http://127.0.0.1:8750`) and matching auth token. The plugin registers the
open IDB over `/pool/ws`; MCP clients use the normal pool `/mcp` or `/sse`
endpoint and see it as an external session.

The pool does not own the lifecycle of externally registered GUI sessions:
disconnecting from the pool does not close the IDB or IDA. Explicit save
requests are forwarded to the Plugin. Disconnect from the IDA menu when
finished.

## Security notes

- Keep HTTP listeners on loopback unless remote access is required.
- Always configure `--auth-token` or `IDA_MCP_AUTH_TOKEN` when binding to a
  non-loopback interface. The token also protects `/pool/ws`.
- The GUI Plugin's direct local server has no bearer-token setting; keep it on
  `127.0.0.1`. `ida-pro-mcp --auth-token` protects only an outer HTTP proxy,
  not the direct Plugin listener.
- Unsafe tools, including Python execution and debugger/destructive actions,
  are enabled by default. Use `--safe` for untrusted clients.

## Docker

The Dockerfile expects a locally built, licensed `ida-pro:latest` base image;
the repository cannot distribute IDA Pro.

```sh
docker build -t ida-mcp .
docker run --rm \
  -p 8745:8745 \
  -v /path/to/binaries:/data \
  -e IDA_MCP_AUTH_TOKEN="replace-with-a-secret" \
  ida-mcp
```

| Variable | Default | Description |
|---|---|---|
| `TRANSPORT` | `http://0.0.0.0:8745` | Pool listener URL. |
| `IDA_MCP_AUTH_TOKEN` | unset | Bearer token read by `idalib-pool`; strongly recommended for Docker. |

Connect to `http://<host>:8745/mcp`. Ensure the mounted directory is writable
if IDA needs to create or update IDB files beside the input binaries.

## Development and tests

Transport/pool unit tests that do not initialize a real IDB can be run
separately:

```sh
PYTHONPATH=src uv run python -m unittest \
  tests.test_pool_manager \
  tests.test_server_transport \
  tests.test_streamable_http_transport_spec
```

`tests/test_pool_integration.py` starts real idalib backend processes. The
IDA-facing API suite uses the maintained fixtures:

```sh
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
```

See [devdocs/test-framework.md](devdocs/test-framework.md) for test framework
details.

## Acknowledgments

Forked from [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).
The headless pool and GUI-pool integration are maintained in
[winmin/ida-headless-mcp](https://github.com/winmin/ida-headless-mcp).
