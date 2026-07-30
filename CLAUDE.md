# CLAUDE.md

Guidance for working in this repository.

## What this project is

IDA Pro MCP integration with two supported runtime paths:

- `idalib-pool`: the primary headless, multi-session MCP endpoint.
- IDA GUI Plugin: either serves the current IDB locally or registers it as an
  external session in an HTTP pool.

There is no public `idalib-mcp` command. `idalib_server.py` is an internal
single-IDB backend launched by the pool manager.

## Architecture

Main components:

- `src/ida_pro_mcp/idalib_pool_server.py`: public pool MCP endpoint,
  transport-context routing, management tools, and `/pool/ws` registration.
- `src/ida_pro_mcp/idalib_pool_manager.py`: backend lifecycle, session
  registry, path deduplication, context bindings, and reference counts.
- `src/ida_pro_mcp/idalib_server.py`: internal idalib backend. One process
  holds at most one active IDB and communicates over a Unix socket.
- `src/ida_pro_mcp/pool_websocket.py`: request/response bridge for externally
  registered GUI Plugin sessions.
- `src/ida_pro_mcp/ida_mcp.py`: IDA Plugin loader and native menu UI for local
  server/pool connection control.
- `src/ida_pro_mcp/server.py`: `ida-pro-mcp` installer and stdio/HTTP bridge
  for the GUI Plugin's local server.
- `src/ida_pro_mcp/ida_mcp/`: IDA-facing tool/resource implementations and
  the vendored MCP transport.

Pool routing is explicit `session_id` first, then the caller's MCP transport
context binding. There is no global default session, LRU eviction, or enforced
`max_instances` cap. Local sessions are reference-counted; the last close
saves the IDB and stops its backend. GUI sessions are externally managed.

Important API modules:

- `api_core.py`: IDB metadata, functions, strings, imports
- `api_analysis.py`: decompilation, disassembly, xrefs, paths, pattern search
- `api_memory.py`: bytes/ints/strings, patching
- `api_types.py`: structs, type inference, type application
- `api_modify.py`: comments, renaming, asm patching
- `api_stack.py`: stack frame operations
- `api_debug.py`: debugger control; unsafe/low priority for IDA API tests
- `api_python.py`: execute Python in IDA context
- `api_resources.py`: `ida://` MCP resources
- `api_survey.py` / `api_composite.py`: higher-level analysis workflows

## Core implementation rules

### IDA thread safety

All IDA SDK calls must run on the main thread:

```python
from .rpc import tool
from .sync import idasync

@tool
@idasync
def my_tool(...):
    ...
```

### API conventions

- Prefer batch-first APIs where the surrounding module uses them.
- Use full type hints and `Annotated[...]` descriptions; function docstrings
  become MCP tool descriptions.
- Parse addresses with `parse_address()`.
- Normalize batch input with `normalize_list_input()` or
  `normalize_dict_list()`.
- Use shared pagination/filtering helpers from `utils.py`.

### Unsafe operations

Debugger, arbitrary-code, or destructive operations should be marked unsafe:

```python
from .rpc import tool, unsafe

@unsafe
@tool
@idasync
def dangerous_op(...):
    ...
```

Unsafe tools are enabled by default and disabled by `--safe`.

## Development commands

### Headless pool

```bash
uv run idalib-pool
uv run idalib-pool --transport http://127.0.0.1:8750
uv run idalib-pool --safe
```

The first backend is created for tool discovery; further backends are spawned
on demand. `--max-instances` is currently a compatibility argument, not a
hard limit or pre-warm count.

### GUI Plugin

```bash
uv run ida-pro-mcp --install
uv run ida-pro-mcp --uninstall
uv run ida-pro-mcp --list-clients
uv run ida-pro-mcp --config
```

In IDA use `MCP > Run Local MCP Server` or `MCP > Connect to Pool`. Those modes
are mutually exclusive. Pool connection requires an HTTP pool because the
Plugin registers over `/pool/ws`.

## Testing

There are two separate layers.

Pure-Python/unit transport and pool tests live in top-level `tests/`:

```bash
PYTHONPATH=src uv run python -m unittest \
  tests.test_pool_manager \
  tests.test_pool_websocket_bridge \
  tests.test_pool_websocket_server \
  tests.test_server_transport \
  tests.test_streamable_http_transport_spec
```

`tests/test_pool_integration.py` starts real idalib backend processes and must
be treated as an integration test.

IDA-facing tests live under `src/ida_pro_mcp/ida_mcp/tests/` and are registered
with `@test`:

```bash
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
uv run ida-mcp-test tests/crackme03.elf -c api_analysis
uv run ida-mcp-test tests/typed_fixture.elf -p "*stack*"
```

Tests belong in the matching separate `test_*.py` module, not inline beside
the API implementation. Use `@test(binary="...")` for fixture-specific tests
and `skip_test(reason)` for justified runtime skips.

### Coverage

```bash
uv run coverage erase
uv run coverage run -m ida_pro_mcp.test tests/crackme03.elf -q
uv run coverage run --append -m ida_pro_mcp.test tests/typed_fixture.elf -q
uv run coverage report --show-missing
```

Test expectations:

- Prefer semantic assertions over weak field-existence checks.
- Prefer round-trip tests for mutating APIs and restore modified state.
- If a test exposes incorrect behavior, fix the implementation instead of
  weakening the assertion.
- Expect some IDA/Hex-Rays variance; guarded assertions or explicit runtime
  skips are acceptable when justified.
- Do not run integration tests against an IDB or server owned by another user
  or process.

See `devdocs/test-framework.md` for framework details.

## Practical notes

- Server/Plugin Python: 3.11+
- IDA Pro: 8.3+; 9.x recommended
- IDA Free is not supported
- If IDA uses the wrong Python, use `idapyswitch`
- Keep MCP listeners on loopback unless remote access is required; use
  `--auth-token`/`IDA_MCP_AUTH_TOKEN` for non-loopback HTTP listeners.
