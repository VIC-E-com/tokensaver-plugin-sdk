import { TextDecoder } from "node:util";

export const MAX_CONTENT_BYTES = 16 << 20;

const API_VERSION = 1;
const MAX_FRAME_BYTES = 24 << 20;
const MAX_HEADER_BYTES = 8 << 10;
const MAX_HEADERS = 32;
const MAX_BUFFER_BYTES = MAX_FRAME_BYTES + (1 << 20);
const MAX_ENCODED_CONTENT_LENGTH = Math.ceil(MAX_CONTENT_BYTES / 3) * 4;
const MISSING = Symbol("missing JSON-RPC id");
const PASS = Object.freeze({ action: "pass" });

export class ProtocolError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "ProtocolError";
  }
}

export class ActionError extends TypeError {
  constructor(message, options) {
    super(message, options);
    this.name = "ActionError";
  }
}

export function passOutput() {
  return PASS;
}

export function optimized(content) {
  if (typeof content !== "string") {
    throw new TypeError("optimized content must be a string");
  }
  if (content.length === 0) {
    throw new ActionError("optimized content cannot be empty");
  }
  if (content.includes("\0")) {
    throw new ActionError("optimized content cannot contain NUL bytes");
  }
  if (!hasValidUnicodeScalars(content)) {
    throw new ActionError("optimized content must be valid UTF-8");
  }
  if (Buffer.byteLength(content, "utf8") > MAX_CONTENT_BYTES) {
    throw new ActionError("optimized content exceeds the size limit");
  }
  return Object.freeze({ action: "optimize", content });
}

export async function serve(identity, optimizer, input, output) {
  if (optimizer == null) {
    throw new TypeError("tokensaver plugin optimizer is required");
  }
  if (input == null || typeof input[Symbol.asyncIterator] !== "function") {
    throw new TypeError("tokensaver plugin input must be an async binary iterable");
  }
  if (output == null || typeof output.write !== "function") {
    throw new TypeError("tokensaver plugin output must be writable");
  }

  const reader = new ByteReader(input);
  let initialized = false;
  while (true) {
    const frame = await readFrame(reader);
    if (frame === null) {
      return;
    }
    let request;
    try {
      request = JSON.parse(decodeUtf8(frame));
    } catch (error) {
      throw new ProtocolError("invalid TSPP JSON", { cause: error });
    }
    if (!isRecord(request)) {
      throw new ProtocolError("invalid TSPP JSON");
    }

    const requestId = Object.hasOwn(request, "id") ? request.id : MISSING;
    if (request.jsonrpc !== "2.0") {
      await writeError(output, requestId, -32600, "jsonrpc must be 2.0");
      continue;
    }

    switch (request.method) {
      case "initialize": {
        if (!validInitializeParams(request.params)) {
          await writeError(output, requestId, -32602, "invalid initialize params");
          break;
        }
        if (request.params.apiVersion !== API_VERSION) {
          await writeError(output, requestId, -32602, "unsupported apiVersion");
          break;
        }
        initialized = true;
        await writeResult(output, requestId, {
          apiVersion: API_VERSION,
          pluginId: identity.pluginId,
          version: identity.version,
        });
        break;
      }
      case "optimize": {
        if (!initialized) {
          await writeError(output, requestId, -32002, "plugin is not initialized");
          break;
        }
        if (!validOptimizeParams(request.params)) {
          await writeError(output, requestId, -32602, "invalid optimize params");
          break;
        }
        const decoded = decodeRequest(request.params);
        if (typeof decoded === "string") {
          await writeError(output, requestId, -32602, decoded);
          break;
        }
        let action;
        try {
          action = await callOptimizer(optimizer, decoded);
        } catch {
          await writeError(output, requestId, -32603, "optimizer raised an exception");
          break;
        }
        try {
          await writeAction(output, requestId, action);
        } catch (error) {
          if (error instanceof ProtocolError) {
            throw error;
          }
          await writeError(output, requestId, -32603, "unsafe optimized content");
        }
        break;
      }
      case "shutdown":
        return;
      default:
        await writeError(output, requestId, -32601, "method not found");
    }
  }
}

export async function run(identity, optimizer) {
  try {
    await serve(identity, optimizer, process.stdin, process.stdout);
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown protocol error";
    const record = JSON.stringify({
      level: "error",
      source: "tokensaver-plugin-sdk",
      message,
    });
    try {
      await writeChunk(process.stderr, Buffer.from(`${record}\n`, "utf8"));
    } catch {
      // A broken diagnostic stream must not contaminate protocol stdout.
    }
  }
}

function hasValidUnicodeScalars(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return false;
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function decodeUtf8(value) {
  return new TextDecoder("utf-8", { fatal: true }).decode(value);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isInteger(value, minimum, maximum) {
  return Number.isInteger(value) && value >= minimum && value <= maximum;
}

function validInitializeParams(params) {
  return isRecord(params)
    && isInteger(params.apiVersion, 0, 0xffffffff)
    && typeof params.host === "string"
    && isInteger(params.budgetMs, 0, 0xffffffff);
}

function validOptimizeParams(params) {
  return isRecord(params)
    && typeof params.kind === "string"
    && typeof params.program === "string"
    && isInteger(params.exitCode, -0x80000000, 0x7fffffff)
    && typeof params.encoding === "string"
    && typeof params.content === "string"
    && isInteger(params.budgetMs, 0, 0xffffffff);
}

function decodeRequest(params) {
  if (params.encoding !== "base64") {
    return "encoding must be base64";
  }
  if (params.content.length > MAX_ENCODED_CONTENT_LENGTH) {
    return "decoded content exceeds 16 MiB";
  }
  if (!isStrictBase64(params.content)) {
    return "content is not valid base64";
  }
  const bytes = Buffer.from(params.content, "base64");
  if (bytes.length > MAX_CONTENT_BYTES) {
    return "decoded content exceeds 16 MiB";
  }
  if (bytes.includes(0)) {
    return "decoded content contains NUL bytes";
  }
  let text;
  try {
    text = decodeUtf8(bytes);
  } catch {
    return "decoded content is not UTF-8";
  }
  return Object.freeze({
    kind: params.kind,
    program: params.program,
    exitCode: params.exitCode,
    text,
    budgetMs: params.budgetMs,
  });
}

function isStrictBase64(value) {
  if (value.length % 4 !== 0) {
    return false;
  }
  return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
}

async function callOptimizer(optimizer, request) {
  if (typeof optimizer === "function") {
    return optimizer(request);
  }
  if (optimizer !== null && typeof optimizer.optimize === "function") {
    return optimizer.optimize(request);
  }
  throw new TypeError("optimizer must be a function or expose optimize(request)");
}

async function writeAction(output, requestId, action) {
  if (action === PASS || (isRecord(action) && action.action === "pass" && !Object.hasOwn(action, "content"))) {
    await writeResult(output, requestId, { action: "pass" });
    return;
  }
  if (isRecord(action) && action.action === "optimize" && typeof action.content === "string") {
    let safe;
    try {
      safe = optimized(action.content);
    } catch {
      safe = null;
    }
    if (safe !== null) {
      await writeResult(output, requestId, {
        action: "optimize",
        content: Buffer.from(safe.content, "utf8").toString("base64"),
      });
      return;
    }
  }
  await writeError(output, requestId, -32603, "unsafe optimized content");
}

async function writeResult(output, requestId, result) {
  const response = { jsonrpc: "2.0", result };
  if (requestId !== MISSING) {
    response.id = requestId;
  }
  await writeFrame(output, response);
}

async function writeError(output, requestId, code, message) {
  const response = { jsonrpc: "2.0", error: { code, message } };
  if (requestId !== MISSING) {
    response.id = requestId;
  }
  await writeFrame(output, response);
}

async function writeFrame(output, value) {
  let payload;
  try {
    payload = Buffer.from(JSON.stringify(value), "utf8");
  } catch (error) {
    throw new ProtocolError("serialize TSPP response failed", { cause: error });
  }
  if (payload.length === 0 || payload.length > MAX_FRAME_BYTES) {
    throw new ProtocolError("invalid TSPP Content-Length");
  }
  await writeChunk(output, Buffer.from(`Content-Length: ${payload.length}\r\n\r\n`, "ascii"));
  await writeChunk(output, payload);
}

function writeChunk(output, chunk) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const onError = (error) => {
      if (!settled) {
        settled = true;
        reject(new ProtocolError("write TSPP response failed", { cause: error }));
      }
    };
    if (typeof output.once === "function") {
      output.once("error", onError);
    }
    try {
      output.write(chunk, (error) => {
        if (error) {
          onError(error);
        } else if (!settled) {
          settled = true;
          if (typeof output.off === "function") {
            output.off("error", onError);
          }
          resolve();
        }
      });
    } catch (error) {
      if (typeof output.off === "function") {
        output.off("error", onError);
      }
      onError(error);
    }
  });
}

class ByteReader {
  constructor(input) {
    this.iterator = input[Symbol.asyncIterator]();
    this.chunks = [];
    this.offset = 0;
    this.total = 0;
    this.done = false;
  }

  async fill() {
    while (!this.done) {
      let next;
      try {
        next = await this.iterator.next();
      } catch (error) {
        throw new ProtocolError("read TSPP stream failed", { cause: error });
      }
      if (next.done) {
        this.done = true;
        return false;
      }
      if (!(next.value instanceof Uint8Array)) {
        throw new ProtocolError("TSPP streams must be binary");
      }
      if (next.value.byteLength === 0) {
        continue;
      }
      if (next.value.byteLength > MAX_BUFFER_BYTES || this.total + next.value.byteLength > MAX_BUFFER_BYTES) {
        throw new ProtocolError("TSPP buffered input exceeds the size limit");
      }
      this.chunks.push(Buffer.from(next.value));
      this.total += next.value.byteLength;
      return true;
    }
    return false;
  }

  find(byte, limit) {
    let scanned = 0;
    for (let index = 0; index < this.chunks.length; index += 1) {
      const chunk = this.chunks[index];
      const start = index === 0 ? this.offset : 0;
      const available = Math.min(chunk.length - start, limit + 1 - scanned);
      const found = chunk.indexOf(byte, start);
      if (found >= start && found < start + available) {
        return scanned + found - start;
      }
      scanned += available;
      if (scanned > limit) {
        return -2;
      }
    }
    return -1;
  }

  take(length) {
    const result = Buffer.allocUnsafe(length);
    let written = 0;
    while (written < length) {
      const chunk = this.chunks[0];
      const available = chunk.length - this.offset;
      const count = Math.min(available, length - written);
      chunk.copy(result, written, this.offset, this.offset + count);
      written += count;
      this.offset += count;
      this.total -= count;
      if (this.offset === chunk.length) {
        this.chunks.shift();
        this.offset = 0;
      }
    }
    return result;
  }

  async readLine(limit) {
    while (true) {
      const position = this.find(0x0a, limit);
      if (position >= 0) {
        return this.take(position + 1);
      }
      if (position === -2 || this.total > limit) {
        throw new ProtocolError("TSPP frame headers exceed the size limit");
      }
      if (!(await this.fill())) {
        return this.total === 0 ? null : this.take(this.total);
      }
    }
  }

  async readExact(length) {
    while (this.total < length) {
      if (!(await this.fill())) {
        throw new ProtocolError("read TSPP frame body failed");
      }
    }
    return this.take(length);
  }
}

async function readFrame(reader) {
  let contentLength = null;
  let headerBytes = 0;
  for (let headerCount = 0; headerCount <= MAX_HEADERS; headerCount += 1) {
    const rawLine = await reader.readLine(MAX_HEADER_BYTES + 1);
    if (rawLine === null) {
      if (headerCount === 0) {
        return null;
      }
      throw new ProtocolError("TSPP frame has no Content-Length");
    }
    headerBytes += rawLine.length;
    if (headerBytes > MAX_HEADER_BYTES) {
      throw new ProtocolError("TSPP frame headers exceed the size limit");
    }
    let end = rawLine.length;
    while (end > 0 && (rawLine[end - 1] === 0x0a || rawLine[end - 1] === 0x0d)) {
      end -= 1;
    }
    const line = rawLine.subarray(0, end);
    if (line.length === 0) {
      if (contentLength !== null) {
        return reader.readExact(contentLength);
      }
      continue;
    }
    const separator = line.indexOf(0x3a);
    if (separator < 0) {
      throw new ProtocolError("malformed TSPP frame header");
    }
    let name;
    try {
      name = decodeUtf8(line.subarray(0, separator)).trim().toLowerCase();
    } catch (error) {
      throw new ProtocolError("malformed TSPP frame header", { cause: error });
    }
    if (name === "content-length") {
      let value;
      try {
        value = decodeUtf8(line.subarray(separator + 1)).trim();
      } catch (error) {
        throw new ProtocolError("invalid TSPP Content-Length", { cause: error });
      }
      if (!/^[+-]?[0-9]+$/.test(value)) {
        throw new ProtocolError("invalid TSPP Content-Length");
      }
      const length = Number(value);
      if (!Number.isSafeInteger(length) || length <= 0 || length > MAX_FRAME_BYTES) {
        throw new ProtocolError("invalid TSPP Content-Length");
      }
      contentLength = length;
    }
  }
  throw new ProtocolError("too many TSPP frame headers");
}
