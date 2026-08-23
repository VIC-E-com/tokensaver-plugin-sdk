package tokensaverplugin

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Run serves TSPP v1 over stdin and stdout until shutdown or EOF.
//
// Protocol failures are emitted as one structured JSON record on stderr.
// stdout remains reserved exclusively for framed TSPP messages.
func Run(identity Identity, optimizer Optimizer) {
	runWithStreams(identity, optimizer, os.Stdin, os.Stdout, os.Stderr)
}

func runWithStreams(identity Identity, optimizer Optimizer, input io.Reader, output, diagnostics io.Writer) {
	if err := Serve(identity, optimizer, input, output); err != nil {
		record := struct {
			Level   string `json:"level"`
			Source  string `json:"source"`
			Message string `json:"message"`
		}{
			Level:   "error",
			Source:  "tokensaver-plugin-sdk",
			Message: err.Error(),
		}
		if encodeErr := json.NewEncoder(diagnostics).Encode(record); encodeErr != nil {
			_, _ = fmt.Fprintln(diagnostics, `{"level":"error","source":"tokensaver-plugin-sdk","message":"could not encode protocol error"}`)
		}
	}
}
