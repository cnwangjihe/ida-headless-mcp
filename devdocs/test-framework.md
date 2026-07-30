# IDA Pro MCP Test Framework

This repository has two test layers with different runtime requirements:

1. Top-level `unittest` tests cover the pool, transports, GUI/pool bridge, and
   lifecycle logic. Most are pure Python; `test_pool_integration.py` starts
   real idalib backends.
2. The custom IDA-facing framework opens a fixture with idalib and runs tests
   registered with `@test` from `src/ida_pro_mcp/ida_mcp/tests/`.

Do not treat the two layers as interchangeable: the second layer initializes
IDA and may create or update IDB files.

## Repository layout

```text
src/ida_pro_mcp/
├── test.py                         # ida-mcp-test command
└── ida_mcp/
    ├── framework.py                # @test, runner, assertions, data helpers
    ├── api_*.py                    # MCP tool/resource implementations
    └── tests/
        ├── test_api_core.py
        ├── test_api_analysis.py
        ├── test_api_memory.py
        ├── test_api_modify.py
        ├── test_api_types.py
        ├── test_api_stack.py
        ├── test_api_resources.py
        ├── test_api_python.py
        ├── test_tool_metadata.py
        ├── test_framework_helpers.py
        ├── test_utils.py
        └── test_typed_fixture.py
tests/
├── test_pool_manager.py            # pure-Python pool/routing tests
├── test_pool_websocket_*.py        # GUI external-session bridge tests
├── test_*transport*.py             # MCP transport tests
├── test_pool_integration.py        # starts real idalib backend processes
├── crackme03.elf                    # general IDA API fixture
└── typed_fixture.elf                # types/globals/stack fixture
```

## IDA-facing test registration

Import the decorator and helpers from `framework.py`:

```python
from ..framework import test, assert_has_keys, assert_shape, skip_test
from ..api_core import idb_meta


@test()
def test_idb_meta_shape():
    result = idb_meta()
    assert_has_keys(result, "path", "module", "base")
```

Tests belong in the matching separate `src/ida_pro_mcp/ida_mcp/tests/test_*.py`
module. The command-line runner imports every module in that package whose
name starts with `test_`; importing a module registers its decorated tests in
the global `TESTS` registry.

The framework still supports inline registration internally, but separate
test modules are the maintained project convention.

### `@test` parameters

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `binary` | `str` | `""` | Run only when the opened fixture's basename matches. |
| `skip` | `bool` | `False` | Unconditionally mark the test skipped. |

Use `skip_test(reason)` for a runtime condition:

```python
@test()
def test_first_function():
    address = get_any_function()
    if address is None:
        skip_test("binary has no functions")
    ...
```

Returning early is not a skip; it records a passed test. Use `skip_test` when
the result should be visible as skipped.

### Categories and patterns

The category comes from the test module name with the `test_` prefix removed:

- `tests/test_api_core.py` -> `api_core`
- `tests/test_framework_helpers.py` -> `framework_helpers`

Test name filters use shell-style glob patterns via `fnmatch`, for example
`"*decompile*"`.

## Assertion and data helpers

Frequently used helpers from `framework.py` include:

| Helper | Purpose |
|---|---|
| `assert_has_keys(mapping, *keys)` | Require mapping keys. |
| `assert_valid_address(value)` | Require a signed/unsigned `0x...` string. |
| `assert_non_empty(value)` | Reject `None` and empty values. |
| `assert_is_list(value, min_length=0)` | Check list type and minimum length. |
| `assert_shape(value, schema)` | Recursively validate a structural schema. |
| `assert_typed_dict(value, type)` | Validate a `TypedDict` contract. |
| `assert_ok(result, *keys)` | Require success and selected result keys. |
| `assert_error(result, contains=...)` | Require an error result and optional text. |
| `optional(schema)` | Mark a shape value optional. |
| `list_of(schema)` | Describe repeated values in a shape. |
| `get_any_function()` | Return a usable function address or `None`. |
| `get_any_string()` | Return a usable string address or `None`. |

Prefer structural and semantic assertions to checks that only prove a key
exists. For mutating APIs, verify a round trip and restore the original IDB
state in `finally`.

Example:

```python
@test()
def test_rename_roundtrip():
    address = get_any_function()
    if address is None:
        skip_test("binary has no functions")

    original = lookup_funcs(address)[0]["fn"]["name"]
    try:
        rename({"func": [{"addr": address, "name": "__mcp_test__"}]})
        assert lookup_funcs(address)[0]["fn"]["name"] == "__mcp_test__"
    finally:
        rename({"func": [{"addr": address, "name": original}]})
```

## Running the IDA-facing suite

The public runner is `ida-mcp-test`:

```bash
# Run the tests applicable to a fixture
uv run ida-mcp-test tests/crackme03.elf

# Quiet summary
uv run ida-mcp-test tests/crackme03.elf --quiet

# Category and test-name filters
uv run ida-mcp-test tests/crackme03.elf --category api_analysis
uv run ida-mcp-test tests/typed_fixture.elf --pattern "*stack*"

# Stop on the first failure
uv run ida-mcp-test tests/crackme03.elf --stop-on-failure

# List registered tests without executing them after opening the fixture
uv run ida-mcp-test tests/crackme03.elf --list

# Show IDA console messages
uv run ida-mcp-test tests/crackme03.elf --verbose
```

Short options are `-q`, `-c`, `-p`, `-x`, `-l`, and `-v` respectively.
The runner exits nonzero when no test matches or any selected test fails.

The runner performs this lifecycle:

1. Initialize idalib.
2. Open the requested binary/IDB with auto-analysis enabled.
3. Wait for auto-analysis.
4. Import all IDA test modules and run the selected registered tests.
5. Close the database in a `finally` block.

### Coverage

Coverage is provided by the `coverage` command, not by an
`ida-mcp-test --coverage` option:

```bash
uv run coverage erase
uv run coverage run -m ida_pro_mcp.test tests/crackme03.elf -q
uv run coverage run --append -m ida_pro_mcp.test tests/typed_fixture.elf -q
uv run coverage report --show-missing
```

The maintained coverage configuration is in `pyproject.toml`.

## Running top-level tests

A representative set that does not initialize real idalib:

```bash
PYTHONPATH=src uv run python -m unittest \
  tests.test_pool_manager \
  tests.test_pool_websocket_bridge \
  tests.test_pool_websocket_server \
  tests.test_server_transport \
  tests.test_stdio_transport_spec \
  tests.test_streamable_http_transport_spec
```

Complete discovery includes `tests/test_pool_integration.py` and therefore
starts real backend processes:

```bash
PYTHONPATH=src uv run python -m unittest discover -s tests -p 'test_*.py'
```

Use complete discovery only when `IDADIR` and the licensed IDA environment are
available and it is safe to start dedicated test backends.

## Adding a test

1. Choose the correct layer: pure pool/transport behavior belongs in top-level
   `unittest`; IDA API behavior belongs in the custom framework.
2. Put an IDA test in the matching `ida_mcp/tests/test_*.py` file and import
   the API under test directly.
3. Use `@test(binary="fixture-name")` only when the assertion depends on that
   fixture's symbols or layout.
4. Prefer public behavior over implementation details.
5. For mutation, restore state even when the assertion fails.
6. Run the narrow test first, then both maintained fixtures when appropriate.

Fixture intent:

- `crackme03.elf`: compact general reverse-engineering regression fixture.
- `typed_fixture.elf`: named types, globals, structs, locals, and stack-frame
  coverage.

IDA and Hex-Rays output can vary across supported versions. A guarded
assertion or explicit runtime skip is acceptable when the variance is real
and documented; weakening a test solely to hide a product defect is not.
