# TokenSaver Plugin SDK for Go

This standard-library-only module implements TokenSaver Plugin Protocol (TSPP)
v1 framing, handshake, base64 conversion, bounded validation, panic isolation,
and graceful shutdown. It contains no TokenSaver optimization heuristics.

```go
package main

import tsp "github.com/VIC-E-com/tokensaver-plugin-sdk/sdk/go/tokensaverplugin"

const pluginID = "com.example.my-optimizer"
const version = "1.0.0"

func main() {
    tsp.Run(tsp.Identity{PluginID: pluginID, Version: version},
        tsp.OptimizerFunc(func(request tsp.Request) tsp.Action {
            return tsp.Pass()
        }))
}
```

Use `Optimized` to construct a proposal. It rejects empty output, NUL bytes,
and payloads over 16 MiB. TokenSaver independently checks UTF-8 safety and the
minimum 20 percent reduction before using any proposal.

Run `go test ./...` in this directory. Use `tsp test`, `tsp bench`, and
`tsp validate` against the built executable and its `plugin.json` before release.
