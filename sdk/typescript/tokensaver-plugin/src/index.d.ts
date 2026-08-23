export const MAX_CONTENT_BYTES: number;

export interface Identity {
  readonly pluginId: string;
  readonly version: string;
}

export interface Request {
  readonly kind: string;
  readonly program: string;
  readonly exitCode: number;
  readonly text: string;
  readonly budgetMs: number;
}

export interface PassAction {
  readonly action: "pass";
}

export interface OptimizeAction {
  readonly action: "optimize";
  readonly content: string;
}

export type Action = PassAction | OptimizeAction;
export type MaybePromise<T> = T | PromiseLike<T>;
export type OptimizerCallable = (request: Request) => MaybePromise<Action>;
export interface Optimizer {
  optimize(request: Request): MaybePromise<Action>;
}
export type OptimizerLike = Optimizer | OptimizerCallable;

export interface BinaryReadable extends AsyncIterable<Uint8Array> {}
export interface BinaryWritable {
  write(chunk: Uint8Array, callback: (error?: Error | null) => void): boolean;
}

export class ProtocolError extends Error {}
export class ActionError extends TypeError {}

export function passOutput(): PassAction;
export function optimized(content: string): OptimizeAction;
export function serve(
  identity: Identity,
  optimizer: OptimizerLike,
  input: BinaryReadable,
  output: BinaryWritable,
): Promise<void>;
export function run(identity: Identity, optimizer: OptimizerLike): Promise<void>;
