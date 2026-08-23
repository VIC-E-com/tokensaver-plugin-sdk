import {
  optimized,
  passOutput,
  run,
  type Action,
  type Identity,
  type Optimizer,
  type Request,
} from "../src/index.js";

const identity = {
  pluginId: "com.example.typescript-seven",
  version: "1.0.0",
} as const satisfies Identity;

const optimizer = {
  optimize(request: Request): Action {
    return request.text.length > 1_000 ? optimized(request.text.slice(0, 100)) : passOutput();
  },
} satisfies Optimizer;

void run(identity, optimizer);
