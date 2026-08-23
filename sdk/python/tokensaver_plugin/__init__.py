"""Standard-library TSPP v1 runtime for TokenSaver optimizer plugins.

This package contains protocol plumbing only. TokenSaver independently verifies
every optimization proposal before using it.
"""

from __future__ import annotations

import base64
import binascii
import json
import sys
from dataclasses import dataclass
from typing import BinaryIO, Callable, Protocol, TypeAlias, runtime_checkable

API_VERSION = 1
MAX_CONTENT_BYTES = 16 << 20
MAX_FRAME_BYTES = 24 << 20
MAX_HEADER_BYTES = 8 << 10
MAX_HEADERS = 32


class ProtocolError(Exception):
    """A terminal framing, JSON, or stream error."""


class ActionError(ValueError):
    """An unsafe optimization proposal."""


@dataclass(frozen=True, slots=True)
class Identity:
    """Plugin identity compiled into the executable and matched by the host."""

    plugin_id: str
    version: str


@dataclass(frozen=True, slots=True)
class Request:
    """Immutable host-validated command-output optimization request."""

    kind: str
    program: str
    exit_code: int
    text: str
    budget_ms: int


@dataclass(frozen=True, slots=True)
class Action:
    """A safe pass or optimization proposal."""

    action: str
    content: str | None = None


@runtime_checkable
class Optimizer(Protocol):
    """Object form of the only behavior a Python plugin implements."""

    def optimize(self, request: Request) -> Action:
        """Return a pass or safe optimization proposal."""


OptimizerCallable: TypeAlias = Callable[[Request], Action]
OptimizerLike: TypeAlias = Optimizer | OptimizerCallable

_PASS = Action("pass")
_MISSING = object()


def pass_output() -> Action:
    """Return a safe no-change action."""

    return _PASS


def optimized(content: str) -> Action:
    """Construct a non-empty, bounded UTF-8 optimization proposal."""

    if type(content) is not str:
        raise TypeError("optimized content must be a string")
    if not content:
        raise ActionError("optimized content cannot be empty")
    if "\x00" in content:
        raise ActionError("optimized content cannot contain NUL bytes")
    try:
        encoded = content.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ActionError("optimized content must be valid UTF-8") from error
    if len(encoded) > MAX_CONTENT_BYTES:
        raise ActionError("optimized content exceeds the size limit")
    return Action("optimize", content)


def serve(
    identity: Identity,
    optimizer: OptimizerLike,
    input_stream: BinaryIO,
    output_stream: BinaryIO,
) -> None:
    """Serve TSPP v1 on caller-provided binary streams until shutdown or EOF."""

    if optimizer is None:
        raise ValueError("tokensaver plugin optimizer is required")
    if input_stream is None:
        raise ValueError("tokensaver plugin input is required")
    if output_stream is None:
        raise ValueError("tokensaver plugin output is required")

    initialized = False
    while True:
        frame = _read_frame(input_stream)
        if frame is None:
            return
        try:
            request = json.loads(
                frame.decode("utf-8", errors="strict"),
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ProtocolError("invalid TSPP JSON") from error
        if not isinstance(request, dict):
            raise ProtocolError("invalid TSPP JSON")

        request_id = request.get("id", _MISSING)
        if request.get("jsonrpc") != "2.0":
            _write_error(output_stream, request_id, -32600, "jsonrpc must be 2.0")
            continue

        method = request.get("method")
        if method == "initialize":
            params = request.get("params")
            if not _valid_initialize_params(params):
                _write_error(output_stream, request_id, -32602, "invalid initialize params")
                continue
            if params["apiVersion"] != API_VERSION:
                _write_error(output_stream, request_id, -32602, "unsupported apiVersion")
                continue
            initialized = True
            _write_result(
                output_stream,
                request_id,
                {
                    "apiVersion": API_VERSION,
                    "pluginId": identity.plugin_id,
                    "version": identity.version,
                },
            )
        elif method == "optimize":
            if not initialized:
                _write_error(output_stream, request_id, -32002, "plugin is not initialized")
                continue
            params = request.get("params")
            if not _valid_optimize_params(params):
                _write_error(output_stream, request_id, -32602, "invalid optimize params")
                continue
            decoded, message = _decode_request(params)
            if message is not None:
                _write_error(output_stream, request_id, -32602, message)
                continue
            try:
                action = _call_optimizer(optimizer, decoded)
            except BaseException:
                _write_error(output_stream, request_id, -32603, "optimizer raised an exception")
                continue
            _write_action(output_stream, request_id, action)
        elif method == "shutdown":
            return
        else:
            _write_error(output_stream, request_id, -32601, "method not found")


def run(identity: Identity, optimizer: OptimizerLike) -> None:
    """Run TSPP v1 over binary stdin/stdout with structured stderr failures."""

    try:
        serve(identity, optimizer, sys.stdin.buffer, sys.stdout.buffer)
    except BaseException as error:
        record = {
            "level": "error",
            "source": "tokensaver-plugin-sdk",
            "message": str(error),
        }
        try:
            sys.stderr.write(json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n")
            sys.stderr.flush()
        except BaseException:
            pass


def _call_optimizer(optimizer: OptimizerLike, request: Request) -> Action:
    if callable(optimizer):
        return optimizer(request)
    return optimizer.optimize(request)


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _is_int(value: object, minimum: int, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def _valid_initialize_params(params: object) -> bool:
    return (
        isinstance(params, dict)
        and _is_int(params.get("apiVersion"), 0, 0xFFFFFFFF)
        and isinstance(params.get("host"), str)
        and _is_int(params.get("budgetMs"), 0, 0xFFFFFFFF)
    )


def _valid_optimize_params(params: object) -> bool:
    return (
        isinstance(params, dict)
        and isinstance(params.get("kind"), str)
        and isinstance(params.get("program"), str)
        and _is_int(params.get("exitCode"), -0x80000000, 0x7FFFFFFF)
        and isinstance(params.get("encoding"), str)
        and isinstance(params.get("content"), str)
        and _is_int(params.get("budgetMs"), 0, 0xFFFFFFFF)
    )


def _decode_request(params: dict[str, object]) -> tuple[Request, str | None]:
    if params["encoding"] != "base64":
        return _empty_request(), "encoding must be base64"
    content = params["content"]
    assert isinstance(content, str)
    if len(content) > ((MAX_CONTENT_BYTES + 2) // 3) * 4:
        return _empty_request(), "decoded content exceeds 16 MiB"
    try:
        decoded = base64.b64decode(content, validate=True)
    except (binascii.Error, ValueError):
        return _empty_request(), "content is not valid base64"
    if len(decoded) > MAX_CONTENT_BYTES:
        return _empty_request(), "decoded content exceeds 16 MiB"
    if b"\x00" in decoded:
        return _empty_request(), "decoded content contains NUL bytes"
    try:
        text = decoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _empty_request(), "decoded content is not UTF-8"
    return (
        Request(
            kind=params["kind"],
            program=params["program"],
            exit_code=params["exitCode"],
            text=text,
            budget_ms=params["budgetMs"],
        ),
        None,
    )


def _empty_request() -> Request:
    return Request("", "", 0, "", 0)


def _write_action(output_stream: BinaryIO, request_id: object, action: object) -> None:
    if isinstance(action, Action) and action.action == "pass" and action.content is None:
        _write_result(output_stream, request_id, {"action": "pass"})
        return
    if isinstance(action, Action) and action.action == "optimize" and action.content is not None:
        try:
            safe = optimized(action.content)
        except (ActionError, TypeError):
            safe = None
        if safe is not None:
            content = safe.content
            assert content is not None
            _write_result(
                output_stream,
                request_id,
                {
                    "action": "optimize",
                    "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
                },
            )
            return
    _write_error(output_stream, request_id, -32603, "unsafe optimized content")


def _write_result(output_stream: BinaryIO, request_id: object, result: object) -> None:
    response: dict[str, object] = {"jsonrpc": "2.0", "result": result}
    if request_id is not _MISSING:
        response["id"] = request_id
    _write_frame(output_stream, response)


def _write_error(
    output_stream: BinaryIO,
    request_id: object,
    code: int,
    message: str,
) -> None:
    response: dict[str, object] = {
        "jsonrpc": "2.0",
        "error": {"code": code, "message": message},
    }
    if request_id is not _MISSING:
        response["id"] = request_id
    _write_frame(output_stream, response)


def _write_frame(output_stream: BinaryIO, value: object) -> None:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ProtocolError("serialize TSPP response failed") from error
    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("invalid TSPP Content-Length")
    header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
    _write_all(output_stream, header)
    _write_all(output_stream, payload)
    flush = getattr(output_stream, "flush", None)
    if flush is not None:
        try:
            flush()
        except Exception as error:
            raise ProtocolError("flush TSPP response failed") from error


def _write_all(output_stream: BinaryIO, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        try:
            written = output_stream.write(remaining)
        except Exception as error:
            raise ProtocolError("write TSPP response failed") from error
        if not isinstance(written, int) or written <= 0 or written > len(remaining):
            raise ProtocolError("write TSPP response failed")
        remaining = remaining[written:]


def _read_frame(input_stream: BinaryIO) -> bytes | None:
    content_length: int | None = None
    header_bytes = 0
    for header_count in range(MAX_HEADERS + 1):
        try:
            line = input_stream.readline(MAX_HEADER_BYTES + 2)
        except Exception as error:
            raise ProtocolError("read TSPP frame header failed") from error
        if not isinstance(line, bytes):
            raise ProtocolError("TSPP streams must be binary")
        if not line:
            if header_count == 0:
                return None
            raise ProtocolError("TSPP frame has no Content-Length")
        header_bytes += len(line)
        if header_bytes > MAX_HEADER_BYTES or (len(line) > MAX_HEADER_BYTES and not line.endswith(b"\n")):
            raise ProtocolError("TSPP frame headers exceed the size limit")
        line = line.rstrip(b"\r\n")
        if not line:
            if content_length is None:
                continue
            return _read_exact(input_stream, content_length)
        separator = line.find(b":")
        if separator < 0:
            raise ProtocolError("malformed TSPP frame header")
        try:
            name = line[:separator].decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as error:
            raise ProtocolError("malformed TSPP frame header") from error
        if name.lower() == "content-length":
            try:
                value = line[separator + 1 :].decode("utf-8", errors="strict").strip()
            except UnicodeDecodeError as error:
                raise ProtocolError("invalid TSPP Content-Length") from error
            length = _parse_content_length(value)
            if length <= 0 or length > MAX_FRAME_BYTES:
                raise ProtocolError("invalid TSPP Content-Length")
            content_length = length
    raise ProtocolError("too many TSPP frame headers")


def _read_exact(input_stream: BinaryIO, length: int) -> bytes:
    output = bytearray(length)
    view = memoryview(output)
    offset = 0
    while offset < length:
        try:
            chunk = input_stream.read(length - offset)
        except Exception as error:
            raise ProtocolError("read TSPP frame body failed") from error
        if not isinstance(chunk, bytes):
            raise ProtocolError("TSPP streams must be binary")
        if not chunk:
            raise ProtocolError("read TSPP frame body failed")
        if len(chunk) > length - offset:
            raise ProtocolError("read TSPP frame body failed")
        view[offset : offset + len(chunk)] = chunk
        offset += len(chunk)
    return bytes(output)


def _parse_content_length(value: str) -> int:
    digits = value[1:] if value[0:1] in {"+", "-"} else value
    if not digits or not digits.isascii() or not digits.isdigit():
        raise ProtocolError("invalid TSPP Content-Length")
    return int(value, 10)


__all__ = [
    "Action",
    "ActionError",
    "Identity",
    "MAX_CONTENT_BYTES",
    "Optimizer",
    "OptimizerCallable",
    "OptimizerLike",
    "ProtocolError",
    "Request",
    "optimized",
    "pass_output",
    "run",
    "serve",
]
