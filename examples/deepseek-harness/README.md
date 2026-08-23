# DeepSeek Harness Output Optimizer

This community TokenSaver plugin reduces repetitive development output from
DeepSeek Harness workspaces while retaining command headers, final summaries,
warnings, failures, and nearby diagnostic context.

The optimizer is deliberately narrow. It runs directly for the `dsh` command.
For Node.js package runners, it first requires a DeepSeek Harness marker such as
`@deepseek-ai/dsh-` or `DeepSeek Harness`; unrelated npm, pnpm, Bun, and Node.js
output passes through unchanged. It does not read files, use the network,
inherit credentials, or retain state between requests.

The implementation applies the following safety rules:

- preserve the first 12 and final 20 lines;
- preserve recognized test and task summaries;
- preserve warnings and failures with neighboring context;
- replace only contiguous routine gaps with an explicit omitted-line count;
- return `pass` unless the result saves at least 20 percent by UTF-8 byte count.

DeepSeek and DeepSeek Harness are names of their respective owners. This
community integration is not affiliated with or endorsed by DeepSeek.
