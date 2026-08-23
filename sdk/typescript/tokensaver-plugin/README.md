# TokenSaver Plugin SDK for TypeScript

This zero-runtime-dependency package ships a JavaScript TSPP v1 runtime and
TypeScript declarations. It provides bounded framing, strict base64 and UTF-8
validation, immutable requests and actions, sync/async exception isolation,
write backpressure handling, and structured diagnostics.

TypeScript-only development pins TypeScript 7.0.2 for strict declaration and consumer-contract
checking. It is a development dependency only. The published runtime remains dependency-free, and
the Rust workbench, Go and Python SDKs, protocol, and TokenSaver host do not depend on TypeScript.

```ts
import { passOutput, run, type Identity, type Request } from "@tokensaver/plugin-sdk";

const identity: Identity = {
  pluginId: "com.example.my-optimizer",
  version: "1.0.0",
};

await run(identity, async (request: Request) => passOutput());
```

Use `optimized(content)` to construct a safe proposal. TokenSaver independently
checks every result and requires a minimum 20 percent reduction. Run `npm ci`, `npm test`, and
`npm run check` before release.

TSPP v1 requires a standalone executable in `plugin.json`. Bundle Node and the
SDK into a self-contained executable using an audited build path; distributed
plugins must not depend on an ambient Node installation.
