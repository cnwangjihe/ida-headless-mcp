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
                      继承的 RPC/control     │ WebSocket /pool/ws
                              Pipes         │
                                    │        │
                              ┌─────▼───┐ ┌──▼──────────────┐
                              │ idalib  │ │ IDA GUI Plugin │
                              │ backend │ │ 当前打开的 IDB │
                              └─────────┘ └─────────────────┘
```

Pool 主进程不会导入 `idapro`。它使用一次性内部 backend 发现工具 schema，
发现完成后立即终止该 backend。每个新建的本地会话都会启动自己的独立
backend，Pool 不会保留空闲 backend 供后续复用。IDA GUI Plugin 也可以把当前
打开的 IDB 注册成由 GUI 外部管理的会话。

本地 backend 使用 Python 跨平台的 `spawn` context 启动。RPC 与取消/关闭命令
分别使用两条继承的 `multiprocessing` Pipe，因此内部通道不会开放 TCP 端口、
Unix socket 路径或公开的命名管道。Windows、Linux 与 macOS 使用同一套生命周期。

### 会话行为

- 一个本地会话独占一个 idalib backend 进程和一个活动 IDB。
- 创建本地会话时总会启动新的 backend；最后一个引用关闭时先保存 IDB，再终止
  对应 backend。
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

PowerShell：

```powershell
$env:IDADIR = "C:\Program Files\IDA Professional 9.1"
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

# 显式指定 IDA；仅对此 pool 进程覆盖 IDADIR
uv run idalib-pool --ida-dir "/path/to/ida-pro" \
  --transport http://127.0.0.1:8750

# 对 HTTP、SSE 和 GUI Pool WebSocket 请求启用 Bearer Token
uv run idalib-pool \
  --transport http://127.0.0.1:8750 \
  --auth-token "replace-with-a-secret"

# 禁用 unsafe 工具；默认会启用这些工具
uv run idalib-pool --safe

# 指定 backend 日志目录
uv run idalib-pool --runtime-dir ./ida-mcp-runtime

# 显示 MCP 请求/响应和内部路由细节
uv run idalib-pool --log-level debug
```

`--ida-dir` 的优先级高于 `IDADIR`。未传该参数时，原有环境变量和 idapro
配置文件自动发现方式保持不变。PowerShell 中包含空格的路径需要加引号，例如
`--ida-dir "C:\Program Files\IDA Professional 9.1"`。

Pool 会在打开 stdio 或网络监听前启动一个临时 backend 并完成工具发现。如果
IDA 无法加载或初始化，非 TUI 模式会立即退出，TUI 模式则在状态区报告失败。
验证完成后该临时 backend 会被关闭，不会作为空闲或预热实例保留。

环境变量 `IDA_MCP_AUTH_TOKEN` 与 `--auth-token` 等效。

### 交互式管理界面

使用显式 HTTP listener 启动可选的 Textual TUI：

```sh
uv run idalib-pool --tui --transport http://127.0.0.1:8750
```

TUI 模式要求交互式终端，以及包含显式端口的 `http://` transport URL；不能与
stdio transport 同时使用。界面会立即显示，IDA 启动验证在后台执行。验证失败时
界面会保留并显示 `FAILED` 状态和诊断日志。

顶部状态区使用紧凑的 `agent/MCP -> IDB session` 树。`A001` 和 `D001` 是在本次
界面生命周期内保持稳定的 agent/database 别名；数字部分至少三位且没有固定位数
上限。每个 database 行还会在方括号中显示 MCP client 收到的 `filename_hash` 真实
session ID，`*` 表示该 agent 当前绑定的 database。共享 database 会分别显示在
每个持有者下面；无持有者或正在关闭的 database 归入
`Unattached / Closing IDBs` 分支。Agent 存活和空闲时间按分钟粒度显示。正在执行
的 `idalib_open` 会立即显示在发起请求的 agent 下方，包括 `OPENING` 状态、完整
输入路径和已耗时；打开成功前不会分配 database 别名，也不计入 refcount。
MCP 请求在 IDA 中执行期间，实际目标 database 行会标记为
`BUSY <tool>`；即使显式 `session_id` 覆盖了 agent 当前绑定，也会标记真实目标。
每个 database 行还会显示本次 Pool/TUI 进程生命周期内完成的调用总数；`show Dxxx`
可查看累计、平均和最长执行时间及最近一次调用，内部 backend tool 映射不会拆成
单独统计。中间区域显示主 Pool 进程在当前 `--log-level` 下的日志，底部单行是
管理控制台。

| 命令 | 行为 |
|---|---|
| `help [command]` | 显示命令帮助。 |
| `show <Axxx\|Dxxx>` | 显示完整 ID、路径、映射、进程信息和 backend 日志位置；也支持唯一 ID 前缀。 |
| `save <Dxxx>` | 保存本地或 GUI 管理的 IDB，不改变 lease。 |
| `close <Dxxx>` | 确认后无视 refcount，保存并强制关闭本地 IDB，同时撤销全部映射；不能强制关闭 GUI 管理的 IDB。 |
| `disconnect <Axxx>` | 确认后拒绝该 agent 的新请求，等待活动请求结束，再释放它持有的全部 lease。 |
| `unregister <Dxxx>` | 确认后从 Pool 移除 GUI 管理的 IDB，但不会在 IDA 中关闭它。 |
| `clear` | 清空当前日志区域。 |
| `quit` | 停止 listener 并关闭 Pool，同时保存本地 IDB。 |

按 Tab 可以补全命令和当前操作适用的 `Axxx`/`Dxxx` 目标。存在多个匹配时会先扩展
公共前缀，继续按 Tab 可循环选择候选项。PageUp/PageDown 可在不离开输入框的
情况下滚动日志。确认框支持 Tab/Shift+Tab 或方向键选择、Enter/Space 激活、
`Y` 确认，以及 `N` 或 Escape 取消。

关系视图由进程内生命周期事件增量更新，不会轮询 MCP Server 或 Pool。每分钟的
UI timer 只用于刷新存活和空闲时间文本。

### 运行时日志

`idalib-pool` 和运行模式下的 `ida-pro-mcp` proxy 都支持
`--log-level {debug,info,warning,error,critical}`。默认级别为 `info`，只显示
MCP transport/session、IDA session/backend 和 GUI 连接的生命周期，以及
warning/error；具体 MCP 请求和响应默认不会输出。使用 `--log-level debug`
可以显示请求/响应预览与耗时、lease 变化、IPC 转发等调试细节。运行时日志写入
stderr，不会污染 stdio JSON-RPC 输出。原有的 Pool `-v`/`--verbose` 参数已由
`--log-level debug` 替代。

请在 MCP Client 连接后通过 `idalib_open` 打开 binary 或 IDB。这样每个新建
session 都会立即拥有对应的引用和 transport context。

### 大结果下载

在 HTTP/SSE Pool 模式中，超大结果会返回预览和由 Pool 自身提供的
`_download_url`。该 URL 返回完整 JSON；启用认证时，下载请求需要携带同一个
Bearer Token。stdio 没有 HTTP 下载端点，因此 Pool 会直接内联返回完整的
structured result，而不会生成不可用的 URL。

下载缓存位于内存中，最多保留最近 100 个结果；Server 重启后缓存会丢失。
重要结果应在被后续大结果淘汰前及时下载。

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

Plugin 每次启动 IDA 时都恢复为 INFO 级别。勾选
**MCP > Verbose Logging** 后，Plugin、transport、JSON-RPC 和 IDA 集成组件会
输出 DEBUG 日志；取消勾选后恢复 INFO。该调试开关不会跨 IDA 重启持久化。

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
