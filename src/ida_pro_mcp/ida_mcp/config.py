import json
import logging
from typing import TypeVar

import ida_netnode

from .sync import idasync


T = TypeVar("T")
logger = logging.getLogger("ida_mcp.ida.config")


@idasync
def config_json_get(key: str, default: T) -> T:
    node = ida_netnode.netnode(f"$ ida_mcp.{key}")
    json_blob: bytes | None = node.getblob(0, "C")
    if json_blob is None:
        return default
    try:
        return json.loads(json_blob)
    except Exception as e:
        logger.warning(
            "Invalid JSON stored in netnode %r: %r: %s",
            key,
            json_blob,
            e,
        )
        return default


@idasync
def config_json_set(key: str, value):
    node = ida_netnode.netnode(f"$ ida_mcp.{key}", 0, True)
    json_blob = json.dumps(value).encode("utf-8")
    node.setblob(json_blob, 0, "C")
