# IDA Pro MCP — Headless Pool Fork

中文 | [English](README.md)

面向 IDA Pro 与 idalib 的 MCP 集成。本项目 fork 自
[mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)，主要维护
headless 多会话 pool，同时保留 IDA GUI Plugin。

## 运行模式

安装后的三个命令用途不同：

| 命令 | 用途 |
|---|---|
| `idalib-pool` | 主要的 headless MCP Server，管理多个 IDB 和 idalib backend 进程。 |
| `ida-pro-mcp` | 安装/配置 GUI Plugin；在 stdio 模式下将 MCP 请求代理到 Plugin 的本地 Server。 |
| `ida-mcp-test` | 使用 idalib 运行 IDA API 测试。 |

项目不再提供公开的 `idalib-mcp` 命令。`ida_pro_mcp.idalib_server` 是
`idalib-pool` 启动的内部单 IDB backend。

## 架构

```text
                               显式 session_id
MCP Client ── stdio/HTTP/SSE ───────────┐
                                        ▼
                            ┌────────────────────────┐
                            │ idalib-pool            │
                            │ context/session router │
                            └───────┬────────┬───────┘
                                    │        │
                           Unix socket       │ WebSocket /pool/ws
                                    │        │
                              ┌─────▼───┐ ┌──▼──────────────┐
                              │ idalib  │ │ IDA GUI Plugin │
                              │ backend │ │ 当前打开的 IDB │
                              └─────────┘ └─────────────────┘
```

Pool 主进程不会导入 `idapro`。它先从一个内部 backend 发现工具 schema，
之后为每个本地会话按需启动独立 backend。IDA GUI Plugin 也可以把当前打开的
IDB 注册成由 GUI 外部管理的会话。

### 会话行为

- 一个本地会话独占一个 idalib backend 进程和一个活动 IDB。
- `idalib_open` 会把返回的会话绑定到调用方的 MCP transport context。
  Streamable HTTP session 和 SSE connection 因此拥有独立的默认路由；stdio
  只有一个 context。
- 普通 IDA 工具中的显式 `session_id` 优先于 context 绑定。
- 默认情况下，重复打开同一个 binary/IDB 会共享已有会话，并为新调用方增加
  reference count。
- `idalib_switch` 只改变调用方自己的 context 绑定，不改变所有权或 reference
  count。
- `idalib_close` 释放一个引用。reference count 归零时，本地 IDB 会先保存，
  对应 backend 随后停止。
- Pool 根据文件名和路径摘要生成 session ID；后续调用必须使用
  `idalib_open` 实际返回的 ID。
- 当前没有 LRU 淘汰，也没有全局默认会话。

CLI 和 Docker 为兼容旧部署仍接受 `--max-instances`，但当前 allocator 只在
启动时创建一个工具发现 backend，其他 backend 均按需创建且没有硬上限。
不要把该参数当作并发限制。

## 前置条件

- [Python](https://www.python.org/downloads/) 3.11+
- [IDA Pro](https://hex-rays.com/ida-pro) 8.3+，且包含
  [idalib](https://docs.hex-rays.com/user-guide/idalib)（推荐 IDA 9.x）
- 已授权的 IDA Pro；IDA Free 不支持本 Plugin
- 无法自动发现 IDA 时，将 `IDADIR` 设置为 IDA 安装目录

示例：

```sh
export IDADIR=/path/to/ida-pro
```

## 安装

从当前仓库安装：

```sh
git clone https://github.com/winmin/ida-headless-mcp.git
cd ida-headless-mcp
uv sync
```

也可以通过 pip 安装当前 `main` 分支：

```sh
pip install https://github.com/winmin/ida-headless-mcp/archive/refs/heads/main.zip
```

## Headless Pool

### 启动 Server

```sh
# stdio，适合由本地 MCP Client 管理进程
uv run idalib-pool

# Streamable HTTP 使用 /mcp，兼容的 SSE 使用 /sse
uv run idalib-pool --transport http://127.0.0.1:8750

# 对 HTTP、SSE 和 GUI Pool WebSocket 请求启用 Bearer Token
uv run idalib-pool \
  --transport http://127.0.0.1:8750 \
  --auth-token "replace-with-a-secret"

# 禁用 unsafe 工具；默认会启用这些工具
uv run idalib-pool --safe

# 指定内部 backend 的 Unix socket 和日志目录
uv run idalib-pool --socket-dir /tmp/ida-mcp-sockets
```

环境变量 `IDA_MCP_AUTH_TOKEN` 与 `--auth-token` 等效。

也可以通过位置参数在启动时打开一个 binary：

```sh
uv run idalib-pool /path/to/binary
```

启动阶段还没有 MCP transport context，因此该会话不会自动绑定到后续 Client。
Client 仍应对相同路径调用一次 `idalib_open`，或者先 `idalib_list` 再
`idalib_switch`，建立自己的 context 绑定。

### MCP Client 配置

本地 stdio：

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "idalib-pool"
    }
  }
}
```

Streamable HTTP：

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "url": "http://127.0.0.1:8750/mcp"
    }
  }
}
```

从源码目录运行：

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

### 典型工作流

```text
idalib_open(input_path="/firmware/httpd")
  -> session_id="httpd_a1b2c3"；调用方 context 绑定到该会话

idalib_open(input_path="/firmware/libcrypto.so")
  -> session_id="libcrypto_d4e5f6"；调用方 context 切换到该会话

decompile(addr="SSL_connect")
  -> 通过调用方当前的 context 绑定路由

decompile(addr="main", session_id="httpd_a1b2c3")
  -> 显式路由，不改变 context 绑定

idalib_close(session_id="httpd_a1b2c3")
idalib_close(session_id="libcrypto_d4e5f6")
  -> 释放该调用方打开的每一个会话
```

每次成功的 `idalib_open` 都应与一次 `idalib_close` 配对。只有管理恢复场景才应
使用 `idalib_close(force=true)`：它会绕过 reference count，并解除其他
context 对该会话的绑定。

### Pool 管理工具

| 工具 | 行为 |
|---|---|
| `idalib_open(input_path, ...)` | 打开或共享 binary/IDB，绑定到调用方并返回 pool 生成的 session ID。 |
| `idalib_close(session_id?, force?)` | 释放引用；本地会话 refcount 归零时保存并关闭。 |
| `idalib_switch(session_id)` | 改变调用方 context 绑定，不修改 refcount。 |
| `idalib_list()` | 列出会话、refcount、所有权类型及调用方的当前绑定。 |
| `idalib_current()` | 返回调用方 context 当前绑定的会话。 |
| `idalib_save(path?, session_id?)` | 保存但不关闭会话。 |
| `idalib_health(session_id?)` | 查询 backend/Plugin readiness。 |
| `idalib_warmup(session_id?, ...)` | 预热自动分析、缓存和 Hex-Rays。 |

Pool 会给 backend 暴露的所有普通 IDA 工具注入可选 `session_id`。可用工具由
运行时发现，README 不再维护容易过期的固定数量。

## IDA GUI Plugin

安装 Plugin，并按需配置受支持的 MCP Client：

```sh
# 交互选择 Client、transport 和 scope
uv run ida-pro-mcp --install

# 非交互示例
uv run ida-pro-mcp --install claude-code --transport streamable-http --scope global

# 查看支持的 Client，或输出通用配置
uv run ida-pro-mcp --list-clients
uv run ida-pro-mcp --config
```

首次安装后需要重启 IDA。

### GUI 本地 Server

在 IDA 中打开 IDB，然后选择 **MCP > Run Local MCP Server**。默认地址为
`127.0.0.1:13337`；可以通过 **MCP > Configuration** 的 IDA 原生对话框修改
host 和 port。当前没有浏览器配置页面。

使用 Streamable HTTP/SSE 安装配置时，Client 直接连接 Plugin Server；使用
stdio 配置时，Client 会启动 `ida-pro-mcp`，再由它代理到 Plugin 的本地
Server。本地 Server 模式与连接 Pool 模式互斥。

### 把 GUI IDB 注册到 Pool

先用 HTTP transport 启动 `idalib-pool`，然后在 IDA 中选择
**MCP > Connect to Pool**，输入 Pool URL（例如
`http://127.0.0.1:8750`）和一致的 auth token。Plugin 会通过 `/pool/ws`
注册当前 IDB；MCP Client 仍通过 Pool 的 `/mcp` 或 `/sse` 端点访问它，并将
它视为 external session。

Pool 不拥有 GUI external session 的生命周期：从 Pool 断开不会关闭 IDB 或
IDA；显式保存请求会转发给 Plugin。完成后应通过 IDA 菜单断开。

## 安全注意事项

- 除非确实需要远程访问，否则 HTTP listener 应保持在 loopback。
- 绑定非 loopback 地址时，必须配置 `--auth-token` 或
  `IDA_MCP_AUTH_TOKEN`；该 token 同样保护 `/pool/ws`。
- GUI Plugin 的直连本地 Server 没有 Bearer Token 设置，应保持监听
  `127.0.0.1`。`ida-pro-mcp --auth-token` 只保护外层 HTTP proxy，不保护
  Plugin 的直连 listener。
- Python 执行、调试器和破坏性操作等 unsafe 工具默认启用。不可信 Client
  应使用 `--safe`。

## Docker

Dockerfile 依赖本地构建且已授权的 `ida-pro:latest` 基础镜像；本仓库不能分发
IDA Pro。

```sh
docker build -t ida-mcp .
docker run --rm \
  -p 8745:8745 \
  -v /path/to/binaries:/data \
  -e IDA_MCP_AUTH_TOKEN="replace-with-a-secret" \
  ida-mcp
```

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `TRANSPORT` | `http://0.0.0.0:8745` | Pool listener URL。 |
| `MAX_INSTANCES` | `10` | 传给 `--max-instances` 的兼容值；当前不是硬上限。 |
| `IDA_MCP_AUTH_TOKEN` | 未设置 | `idalib-pool` 读取的 Bearer Token；Docker 部署强烈建议设置。 |

Client 连接 `http://<host>:8745/mcp`。如果 IDA 需要在输入文件旁创建或更新
IDB，挂载目录必须可写。

## 开发与测试

不需要真实 IDB 的 transport/pool 单元测试可以单独运行：

```sh
PYTHONPATH=src uv run python -m unittest \
  tests.test_pool_manager \
  tests.test_server_transport \
  tests.test_streamable_http_transport_spec
```

`tests/test_pool_integration.py` 会启动真实 idalib backend。IDA API 测试使用仓库
维护的 fixture：

```sh
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
```

测试框架细节见 [devdocs/test-framework.md](devdocs/test-framework.md)。

## 致谢

Fork 自 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)。
Headless Pool 与 GUI-Pool 集成维护在
[winmin/ida-headless-mcp](https://github.com/winmin/ida-headless-mcp)。
