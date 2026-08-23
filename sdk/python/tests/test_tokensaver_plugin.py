import base64
import io
import json
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tokensaver_plugin as tsp


IDENTITY = tsp.Identity("com.tokensaver.python-test", "1.2.3")


def framed(value):
    payload = json.dumps(value, separators=(",", ":")).encode()
    return f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload


def lifecycle(content=b"raw output", *, extras=False):
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"apiVersion": 1, "host": "tokensaver", "budgetMs": 250},
    }
    optimize = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "optimize",
        "params": {
            "kind": "test",
            "program": "python",
            "exitCode": 1,
            "encoding": "base64",
            "content": base64.b64encode(content).decode(),
            "budgetMs": 250,
        },
    }
    if extras:
        initialize["params"]["future"] = True
        initialize["extensions"] = {"trace": True}
        optimize["params"]["future"] = "accepted"
    return framed(initialize) + framed(optimize) + framed({"jsonrpc": "2.0", "method": "shutdown"})


def responses(data):
    source = io.BytesIO(data)
    values = []
    while True:
        payload = tsp._read_frame(source)
        if payload is None:
            return values
        values.append(json.loads(payload))


class PartialWriter(io.BytesIO):
    def write(self, value):
        return super().write(bytes(value[:3]))


class FailingWriter(io.BytesIO):
    def write(self, _value):
        raise OSError("synthetic")


class NoProgressWriter(io.BytesIO):
    def write(self, _value):
        return None


class FailingReader(io.BytesIO):
    def readline(self, _limit=-1):
        raise OSError("synthetic")


class SDKTests(unittest.TestCase):
    def test_actions_and_requests_are_immutable_and_bounded(self):
        self.assertEqual(tsp.pass_output(), tsp.Action("pass"))
        self.assertIs(tsp.pass_output(), tsp.pass_output())
        with self.assertRaises(tsp.ActionError):
            tsp.optimized("")
        with self.assertRaises(tsp.ActionError):
            tsp.optimized("bad\0output")
        with self.assertRaises(tsp.ActionError):
            tsp.optimized("\ud800")
        with self.assertRaises(tsp.ActionError):
            tsp.optimized("x" * (tsp.MAX_CONTENT_BYTES + 1))
        with self.assertRaises(TypeError):
            tsp.optimized(b"bytes")
        class StringSubclass(str):
            pass
        with self.assertRaises(TypeError):
            tsp.optimized(StringSubclass("text"))
        action = tsp.optimized("safe")
        with self.assertRaises(FrozenInstanceError):
            action.content = "changed"

    def test_exact_lifecycle_and_additive_fields(self):
        seen = []

        def optimize(request):
            seen.append(request)
            return tsp.optimized(f"{request.program}:{request.text}")

        output = io.BytesIO()
        tsp.serve(IDENTITY, optimize, io.BytesIO(lifecycle(extras=True)), output)
        result = responses(output.getvalue())
        self.assertEqual(result[0]["result"], {
            "apiVersion": 1,
            "pluginId": IDENTITY.plugin_id,
            "version": IDENTITY.version,
        })
        self.assertEqual(result[1]["result"]["action"], "optimize")
        self.assertEqual(base64.b64decode(result[1]["result"]["content"]), b"python:raw output")
        self.assertEqual(seen, [tsp.Request("test", "python", 1, "raw output", 250)])
        with self.assertRaises(FrozenInstanceError):
            seen[0].text = "changed"

    def test_object_optimizer_and_pass(self):
        class Passer:
            def optimize(self, _request):
                return tsp.pass_output()

        output = io.BytesIO()
        tsp.serve(IDENTITY, Passer(), io.BytesIO(lifecycle()), output)
        self.assertEqual(responses(output.getvalue())[1]["result"], {"action": "pass"})

    def test_rpc_errors_are_recoverable_and_versioned(self):
        cases = [
            ({"jsonrpc": "1.0", "id": 1, "method": "initialize"}, -32600),
            ({"jsonrpc": "2.0", "id": 1, "method": "missing"}, -32601),
            ({"jsonrpc": "2.0", "id": 1, "method": "optimize", "params": {}}, -32002),
            ({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, -32602),
            ({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"apiVersion": 2, "host": "tokensaver", "budgetMs": 1}}, -32602),
        ]
        for request, code in cases:
            with self.subTest(code=code, request=request):
                output = io.BytesIO()
                tsp.serve(IDENTITY, lambda _request: tsp.pass_output(), io.BytesIO(framed(request)), output)
                self.assertEqual(responses(output.getvalue())[0]["error"]["code"], code)

    def test_parameter_types_are_strict(self):
        bad_values = [True, -1, 0x100000000, 1.5, "1"]
        for value in bad_values:
            request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"apiVersion": 1, "host": "tokensaver", "budgetMs": value}}
            output = io.BytesIO()
            tsp.serve(IDENTITY, lambda _request: tsp.pass_output(), io.BytesIO(framed(request)), output)
            self.assertEqual(responses(output.getvalue())[0]["error"]["code"], -32602)

    def test_content_validation_errors(self):
        invalid = [
            ("hex", base64.b64encode(b"raw").decode(), "encoding must be base64"),
            ("base64", "%%%", "content is not valid base64"),
            ("base64", "aGk", "content is not valid base64"),
            ("base64", base64.b64encode(b"bad\0raw").decode(), "decoded content contains NUL bytes"),
            ("base64", base64.b64encode(b"\xff").decode(), "decoded content is not UTF-8"),
        ]
        for encoding, content, message in invalid:
            with self.subTest(message=message):
                stream = lifecycle()
                request = {"jsonrpc": "2.0", "id": 3, "method": "optimize", "params": {"kind": "test", "program": "python", "exitCode": 0, "encoding": encoding, "content": content, "budgetMs": 1}}
                source = stream[: stream.find(framed({"jsonrpc": "2.0", "method": "shutdown"}))] + framed(request)
                output = io.BytesIO()
                tsp.serve(IDENTITY, lambda _request: tsp.pass_output(), io.BytesIO(source), output)
                self.assertEqual(responses(output.getvalue())[-1]["error"]["message"], message)

    def test_optimizer_exceptions_and_forged_actions_are_isolated(self):
        class HostileResult:
            def __eq__(self, _other):
                raise RuntimeError("must not run")

        for optimizer, message in [
            (lambda _request: (_ for _ in ()).throw(RuntimeError("secret")), "optimizer raised an exception"),
            (lambda _request: tsp.Action("optimize", "bad\0output"), "unsafe optimized content"),
            (lambda _request: object(), "unsafe optimized content"),
            (lambda _request: HostileResult(), "unsafe optimized content"),
        ]:
            output = io.BytesIO()
            tsp.serve(IDENTITY, optimizer, io.BytesIO(lifecycle()), output)
            error = responses(output.getvalue())[1]["error"]
            self.assertEqual(error["code"], -32603)
            self.assertEqual(error["message"], message)
            self.assertNotIn("secret", json.dumps(error))

    def test_framing_limits_and_malformed_inputs(self):
        invalid = [
            b"broken\r\n\r\n",
            b"Content-Length: 0\r\n\r\n",
            f"Content-Length: {tsp.MAX_FRAME_BYTES + 1}\r\n\r\n".encode(),
            b"Content-Length: 10_0\r\n\r\n",
            b"Content-Length: 5\r\n\r\nabc",
            b"X: y\r\n",
            b"X:" + b"y" * tsp.MAX_HEADER_BYTES + b"\n",
            (b"X: y\r\n" * (tsp.MAX_HEADERS + 1)) + b"\r\n",
        ]
        for value in invalid:
            with self.subTest(prefix=value[:30]):
                with self.assertRaises(tsp.ProtocolError):
                    tsp._read_frame(io.BytesIO(value))
        self.assertIsNone(tsp._read_frame(io.BytesIO()))

    def test_json_and_stream_failures_are_terminal_without_partial_recovery(self):
        for payload in [b"[]", b'{"value":NaN}', b"\xff"]:
            with self.assertRaises(tsp.ProtocolError):
                tsp.serve(IDENTITY, lambda _request: tsp.pass_output(), io.BytesIO(f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload), io.BytesIO())
        with self.assertRaises(tsp.ProtocolError):
            tsp.serve(IDENTITY, lambda _request: tsp.pass_output(), FailingReader(), io.BytesIO())
        with self.assertRaises(tsp.ProtocolError):
            tsp.serve(IDENTITY, lambda _request: tsp.pass_output(), io.BytesIO(framed({"jsonrpc": "1.0", "id": 1})), FailingWriter())
        with self.assertRaises(tsp.ProtocolError):
            tsp.serve(IDENTITY, lambda _request: tsp.pass_output(), io.BytesIO(framed({"jsonrpc": "1.0", "id": 1})), NoProgressWriter())

    def test_partial_writes_and_flush_are_supported(self):
        output = PartialWriter()
        tsp.serve(IDENTITY, lambda _request: tsp.pass_output(), io.BytesIO(lifecycle()), output)
        self.assertEqual(responses(output.getvalue())[1]["result"], {"action": "pass"})

    def test_independent_servers_are_thread_safe(self):
        barrier = threading.Barrier(8)

        def one(index):
            barrier.wait()
            output = io.BytesIO()
            tsp.serve(tsp.Identity(f"com.example.{index}", "1.0.0"), lambda request: tsp.optimized(f"{index}:{request.text}"), io.BytesIO(lifecycle()), output)
            values = responses(output.getvalue())
            return values[0]["result"]["pluginId"], base64.b64decode(values[1]["result"]["content"]).decode()

        with ThreadPoolExecutor(max_workers=8) as pool:
            values = list(pool.map(one, range(8)))
        self.assertEqual(values, [(f"com.example.{i}", f"{i}:raw output") for i in range(8)])


if __name__ == "__main__":
    unittest.main()
