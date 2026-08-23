import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import test from "node:test";

import {
  ActionError,
  MAX_CONTENT_BYTES,
  ProtocolError,
  optimized,
  passOutput,
  serve,
} from "../src/index.js";

const IDENTITY = Object.freeze({ pluginId: "com.tokensaver.typescript-test", version: "1.2.3" });

function framed(value) {
  const payload = Buffer.from(JSON.stringify(value), "utf8");
  return Buffer.concat([Buffer.from(`Content-Length: ${payload.length}\r\n\r\n`, "ascii"), payload]);
}

function lifecycle(content = Buffer.from("raw output"), extras = false) {
  const initialize = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { apiVersion: 1, host: "tokensaver", budgetMs: 250 },
  };
  const optimize = {
    jsonrpc: "2.0",
    id: 2,
    method: "optimize",
    params: {
      kind: "test",
      program: "node",
      exitCode: 1,
      encoding: "base64",
      content: content.toString("base64"),
      budgetMs: 250,
    },
  };
  if (extras) {
    initialize.params.future = true;
    initialize.extensions = { trace: true };
    optimize.params.future = "accepted";
  }
  return Buffer.concat([framed(initialize), framed(optimize), framed({ jsonrpc: "2.0", method: "shutdown" })]);
}

class Collector extends Writable {
  constructor(options = {}) {
    super(options);
    this.chunks = [];
  }

  _write(chunk, _encoding, callback) {
    this.chunks.push(Buffer.from(chunk));
    setImmediate(callback);
  }

  value() {
    return Buffer.concat(this.chunks);
  }
}

function parseFrames(bytes) {
  const result = [];
  let offset = 0;
  while (offset < bytes.length) {
    const end = bytes.indexOf("\r\n\r\n", offset, "ascii");
    assert.notEqual(end, -1);
    const match = /^Content-Length: ([0-9]+)$/i.exec(bytes.subarray(offset, end).toString("ascii"));
    assert.ok(match);
    const length = Number(match[1]);
    const start = end + 4;
    result.push(JSON.parse(bytes.subarray(start, start + length).toString("utf8")));
    offset = start + length;
  }
  return result;
}

async function execute(input, optimizer, writer = new Collector()) {
  await serve(IDENTITY, optimizer, Readable.from([input]), writer);
  return parseFrames(writer.value());
}

test("actions are immutable and enforce byte-oriented safety limits", () => {
  assert.strictEqual(passOutput(), passOutput());
  assert.ok(Object.isFrozen(passOutput()));
  assert.throws(() => optimized(""), ActionError);
  assert.throws(() => optimized("bad\0output"), ActionError);
  assert.throws(() => optimized("\ud800"), ActionError);
  assert.throws(() => optimized("x".repeat(MAX_CONTENT_BYTES + 1)), ActionError);
  assert.throws(() => optimized(Buffer.from("bytes")), TypeError);
  assert.ok(Object.isFrozen(optimized("safe")));
});

test("exact lifecycle accepts additive v1 fields and freezes the request", async () => {
  let observed;
  const values = await execute(lifecycle(undefined, true), (request) => {
    observed = request;
    assert.ok(Object.isFrozen(request));
    return optimized(`${request.program}:${request.text}`);
  });
  assert.deepEqual(values[0].result, { apiVersion: 1, pluginId: IDENTITY.pluginId, version: IDENTITY.version });
  assert.equal(values[1].result.action, "optimize");
  assert.equal(Buffer.from(values[1].result.content, "base64").toString(), "node:raw output");
  assert.deepEqual(observed, { kind: "test", program: "node", exitCode: 1, text: "raw output", budgetMs: 250 });
});

test("function and object optimizers may return sync or async pass actions", async () => {
  const sync = await execute(lifecycle(), () => passOutput());
  assert.deepEqual(sync[1].result, { action: "pass" });
  const asyncObject = await execute(lifecycle(), { optimize: async () => passOutput() });
  assert.deepEqual(asyncObject[1].result, { action: "pass" });
});

test("JSON-RPC lifecycle errors are bounded and recoverable", async () => {
  const cases = [
    [{ jsonrpc: "1.0", id: 1, method: "initialize" }, -32600],
    [{ jsonrpc: "2.0", id: 1, method: "missing" }, -32601],
    [{ jsonrpc: "2.0", id: 1, method: "optimize", params: {} }, -32002],
    [{ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, -32602],
    [{ jsonrpc: "2.0", id: 1, method: "initialize", params: { apiVersion: 2, host: "tokensaver", budgetMs: 1 } }, -32602],
  ];
  for (const [request, code] of cases) {
    const values = await execute(framed(request), () => passOutput());
    assert.equal(values[0].error.code, code);
  }
});

test("numeric parameter types and ranges are strict", async () => {
  for (const budgetMs of [true, -1, 0x100000000, 1.5, "1"]) {
    const values = await execute(framed({ jsonrpc: "2.0", id: 1, method: "initialize", params: { apiVersion: 1, host: "tokensaver", budgetMs } }), () => passOutput());
    assert.equal(values[0].error.code, -32602);
  }
});

test("base64, NUL, and UTF-8 validation is strict", async () => {
  const invalid = [
    ["hex", Buffer.from("raw").toString("base64"), "encoding must be base64"],
    ["base64", "%%%", "content is not valid base64"],
    ["base64", "aGk", "content is not valid base64"],
    ["base64", Buffer.from("bad\0raw").toString("base64"), "decoded content contains NUL bytes"],
    ["base64", Buffer.from([0xff]).toString("base64"), "decoded content is not UTF-8"],
  ];
  for (const [encoding, content, message] of invalid) {
    const initialize = framed({ jsonrpc: "2.0", id: 1, method: "initialize", params: { apiVersion: 1, host: "tokensaver", budgetMs: 1 } });
    const request = framed({ jsonrpc: "2.0", id: 2, method: "optimize", params: { kind: "test", program: "node", exitCode: 0, encoding, content, budgetMs: 1 } });
    const values = await execute(Buffer.concat([initialize, request]), () => passOutput());
    assert.equal(values[1].error.message, message);
  }
});

test("sync and async optimizer failures do not leak details or corrupt stdout", async () => {
  const optimizers = [
    () => { throw new Error("secret sync detail"); },
    async () => { throw new Error("secret async detail"); },
  ];
  for (const optimizer of optimizers) {
    const values = await execute(lifecycle(), optimizer);
    assert.deepEqual(values[1].error, { code: -32603, message: "optimizer raised an exception" });
    assert.doesNotMatch(JSON.stringify(values), /secret/);
  }
});

test("forged or unsafe actions become internal errors", async () => {
  const hostile = new Proxy({}, {
    get() {
      throw new Error("must not escape");
    },
  });
  for (const action of [{ action: "optimize", content: "bad\0output" }, { action: "pass", content: "unexpected" }, {}, null]) {
    const values = await execute(lifecycle(), () => action);
    assert.deepEqual(values[1].error, { code: -32603, message: "unsafe optimized content" });
  }
  const hostileValues = await execute(lifecycle(), () => hostile);
  assert.deepEqual(hostileValues[1].error, { code: -32603, message: "optimizer raised an exception" });
});

test("framing rejects malformed, oversized, excessive, and truncated input", async () => {
  const invalid = [
    Buffer.from("broken\r\n\r\n"),
    Buffer.from("Content-Length: 0\r\n\r\n"),
    Buffer.from(`Content-Length: ${(24 << 20) + 1}\r\n\r\n`),
    Buffer.from("Content-Length: 10_0\r\n\r\n"),
    Buffer.from("Content-Length: 5\r\n\r\nabc"),
    Buffer.from("X: y\r\n"),
    Buffer.concat([Buffer.from("X:"), Buffer.alloc((8 << 10) + 1, 0x79), Buffer.from("\n")]),
    Buffer.concat([Buffer.from("X: y\r\n".repeat(33)), Buffer.from("\r\n")]),
  ];
  for (const input of invalid) {
    await assert.rejects(() => serve(IDENTITY, () => passOutput(), Readable.from([input]), new Collector()), ProtocolError);
  }
});

test("invalid JSON and binary stream violations are terminal", async () => {
  for (const payload of [Buffer.from("[]"), Buffer.from([0xff])]) {
    const input = Buffer.concat([Buffer.from(`Content-Length: ${payload.length}\r\n\r\n`), payload]);
    await assert.rejects(() => serve(IDENTITY, () => passOutput(), Readable.from([input]), new Collector()), ProtocolError);
  }
  await assert.rejects(() => serve(IDENTITY, () => passOutput(), Readable.from(["text is not binary"]), new Collector()), ProtocolError);
});

test("write failures are terminal and backpressure is respected", async () => {
  const failing = new Writable({
    write(_chunk, _encoding, callback) {
      callback(new Error("synthetic"));
    },
  });
  await assert.rejects(() => serve(IDENTITY, () => passOutput(), Readable.from([framed({ jsonrpc: "1.0", id: 1 })]), failing), ProtocolError);

  const slow = new Collector({ highWaterMark: 1 });
  const values = await execute(lifecycle(), () => passOutput(), slow);
  assert.deepEqual(values[1].result, { action: "pass" });
});

test("independent concurrent servers do not share protocol state", async () => {
  const runs = Array.from({ length: 16 }, async (_, index) => {
    const output = new Collector();
    const identity = { pluginId: `com.example.${index}`, version: "1.0.0" };
    await serve(identity, async (request) => optimized(`${index}:${request.text}`), Readable.from([lifecycle()]), output);
    const values = parseFrames(output.value());
    return [values[0].result.pluginId, Buffer.from(values[1].result.content, "base64").toString()];
  });
  assert.deepEqual(await Promise.all(runs), Array.from({ length: 16 }, (_, index) => [`com.example.${index}`, `${index}:raw output`]));
});
