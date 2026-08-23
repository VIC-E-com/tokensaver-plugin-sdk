package tokensaverplugin

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
)

var testIdentity = Identity{
	PluginID: "com.tokensaver.go-test",
	Version:  "1.2.3",
}

func TestOptimizedEnforcesSDKBoundaries(t *testing.T) {
	if _, err := Optimized(""); !errors.Is(err, ErrEmptyContent) {
		t.Fatalf("Optimized(empty) error = %v", err)
	}
	if _, err := Optimized("bad\x00output"); !errors.Is(err, ErrNULContent) {
		t.Fatalf("Optimized(NUL) error = %v", err)
	}
	if _, err := Optimized(string([]byte{0xff})); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("Optimized(invalid UTF-8) error = %v", err)
	}
	if _, err := Optimized(strings.Repeat("x", MaxContentBytes+1)); !errors.Is(err, ErrContentTooLarge) {
		t.Fatalf("Optimized(oversize) error = %v", err)
	}
	action, err := Optimized("safe")
	if err != nil || action.kind != actionOptimize || action.content != "safe" {
		t.Fatalf("Optimized(safe) = %#v, %v", action, err)
	}
	if action := Pass(); action.kind != actionPass || action.content != "" {
		t.Fatalf("Pass() = %#v", action)
	}
}

func TestExactHostLifecycleReturnsHandshakeAndOptimization(t *testing.T) {
	input := requestStream(t, "test", []byte("raw output"))
	var output bytes.Buffer
	optimizer := OptimizerFunc(func(request Request) Action {
		if request.Kind() != KindTest || request.Program() != "go" || request.ExitCode() != 1 ||
			request.Text() != "raw output" || request.BudgetMS() != 250 {
			t.Fatalf("unexpected request: %#v", request)
		}
		action, err := Optimized(request.Program() + ":" + request.Text())
		if err != nil {
			t.Fatal(err)
		}
		return action
	})
	if err := Serve(testIdentity, optimizer, bytes.NewReader(input), &output); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	responses := responseValues(t, output.Bytes())
	if len(responses) != 2 {
		t.Fatalf("got %d responses, want 2", len(responses))
	}
	if got := responses[0]["result"].(map[string]any); got["apiVersion"] != float64(1) || got["pluginId"] != testIdentity.PluginID || got["version"] != testIdentity.Version {
		t.Fatalf("initialize result = %#v", got)
	}
	result := responses[1]["result"].(map[string]any)
	if result["action"] != "optimize" {
		t.Fatalf("optimize result = %#v", result)
	}
	decoded, err := base64.StdEncoding.DecodeString(result["content"].(string))
	if err != nil || string(decoded) != "go:raw output" {
		t.Fatalf("optimized content = %q, %v", decoded, err)
	}
}

func TestPassAndAdditiveFieldsAreCompatible(t *testing.T) {
	input := framed(t, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"apiVersion": 1, "host": "tokensaver", "budgetMs": 250,
			"futureHostField": true,
		},
		"extensions": map[string]any{"com.example.trace": true},
	})
	input = append(input, framed(t, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "optimize",
		"params": map[string]any{
			"kind": "log", "program": "git", "exitCode": 0,
			"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("raw")),
			"budgetMs": 250, "futureRequestField": "accepted",
		},
	})...)
	input = append(input, framed(t, map[string]any{"jsonrpc": "2.0", "method": "shutdown"})...)
	var output bytes.Buffer
	if err := Serve(testIdentity, OptimizerFunc(func(Request) Action { return Pass() }), bytes.NewReader(input), &output); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	responses := responseValues(t, output.Bytes())
	result := responses[1]["result"].(map[string]any)
	if result["action"] != "pass" {
		t.Fatalf("pass result = %#v", result)
	}
	if _, exists := result["content"]; exists {
		t.Fatalf("pass response contains content: %#v", result)
	}
}

func TestProtocolErrorsAreBoundedAndRecoverable(t *testing.T) {
	tests := []struct {
		name     string
		requests []map[string]any
		code     float64
	}{
		{
			name: "pre-initialize",
			requests: []map[string]any{{
				"jsonrpc": "2.0", "id": 2, "method": "optimize", "params": map[string]any{},
			}},
			code: -32002,
		},
		{
			name: "unsupported major",
			requests: []map[string]any{{
				"jsonrpc": "2.0", "id": 1, "method": "initialize",
				"params": map[string]any{"apiVersion": 2, "host": "tokensaver", "budgetMs": 250},
			}},
			code: -32602,
		},
		{
			name: "malformed base64",
			requests: []map[string]any{
				{
					"jsonrpc": "2.0", "id": 1, "method": "initialize",
					"params": map[string]any{"apiVersion": 1, "host": "tokensaver", "budgetMs": 250},
				},
				{
					"jsonrpc": "2.0", "id": 2, "method": "optimize",
					"params": map[string]any{
						"kind": "test", "program": "go", "exitCode": 0,
						"encoding": "base64", "content": "%%%", "budgetMs": 250,
					},
				},
			},
			code: -32602,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var input []byte
			for _, request := range test.requests {
				input = append(input, framed(t, request)...)
			}
			var output bytes.Buffer
			if err := Serve(testIdentity, OptimizerFunc(func(Request) Action { return Pass() }), bytes.NewReader(input), &output); err != nil {
				t.Fatalf("Serve: %v", err)
			}
			responses := responseValues(t, output.Bytes())
			last := responses[len(responses)-1]
			if got := last["error"].(map[string]any)["code"]; got != test.code {
				t.Fatalf("error code = %v, want %v", got, test.code)
			}
		})
	}
}

func TestOptimizerPanicIsIsolated(t *testing.T) {
	input := requestStream(t, "test", []byte("raw"))
	var output bytes.Buffer
	optimizer := OptimizerFunc(func(Request) Action { panic("intentional test panic") })
	if err := Serve(testIdentity, optimizer, bytes.NewReader(input), &output); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	responses := responseValues(t, output.Bytes())
	if got := responses[1]["error"].(map[string]any)["code"]; got != float64(-32603) {
		t.Fatalf("panic error code = %v", got)
	}
}

func TestUnsafeActionIsRecheckedAtProtocolBoundary(t *testing.T) {
	tests := []Action{
		{kind: actionOptimize, content: ""},
		{kind: actionOptimize, content: "bad\x00output"},
		{kind: actionOptimize, content: string([]byte{0xff})},
		{kind: actionKind(99), content: "unknown"},
	}
	for _, action := range tests {
		var output bytes.Buffer
		optimizer := OptimizerFunc(func(Request) Action { return action })
		if err := Serve(testIdentity, optimizer, bytes.NewReader(requestStream(t, "test", []byte("raw"))), &output); err != nil {
			t.Fatalf("Serve: %v", err)
		}
		responses := responseValues(t, output.Bytes())
		if got := responses[1]["error"].(map[string]any)["code"]; got != float64(-32603) {
			t.Fatalf("unsafe action %#v error code = %v", action, got)
		}
	}
}

func TestRequestValidationRejectsUnsafeOrIncompleteInput(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
	}{
		{
			name:   "missing fields",
			params: map[string]any{"kind": "test"},
		},
		{
			name: "wrong encoding",
			params: map[string]any{
				"kind": "test", "program": "go", "exitCode": 0,
				"encoding": "text", "content": "raw", "budgetMs": 250,
			},
		},
		{
			name: "NUL content",
			params: map[string]any{
				"kind": "test", "program": "go", "exitCode": 0,
				"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte{0}), "budgetMs": 250,
			},
		},
		{
			name: "invalid UTF-8",
			params: map[string]any{
				"kind": "test", "program": "go", "exitCode": 0,
				"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte{0xff}), "budgetMs": 250,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := framed(t, map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": "initialize",
				"params": map[string]any{"apiVersion": 1, "host": "tokensaver", "budgetMs": 250},
			})
			input = append(input, framed(t, map[string]any{
				"jsonrpc": "2.0", "id": 2, "method": "optimize", "params": test.params,
			})...)
			var output bytes.Buffer
			if err := Serve(testIdentity, OptimizerFunc(func(Request) Action { return Pass() }), bytes.NewReader(input), &output); err != nil {
				t.Fatalf("Serve: %v", err)
			}
			responses := responseValues(t, output.Bytes())
			if got := responses[1]["error"].(map[string]any)["code"]; got != float64(-32602) {
				t.Fatalf("request error code = %v", got)
			}
		})
	}
}

func TestParameterDecodersRequireV1FieldsAndBoundDecodedContent(t *testing.T) {
	if _, ok := decodeInitializeParams(nil); ok {
		t.Fatal("missing initialize params were accepted")
	}
	if _, ok := decodeInitializeParams(json.RawMessage(`{"apiVersion":1}`)); ok {
		t.Fatal("incomplete initialize params were accepted")
	}
	if _, ok := decodeOptimizeParams(nil); ok {
		t.Fatal("missing optimize params were accepted")
	}
	params := optimizeParams{
		Kind:     stringPointer("test"),
		Program:  stringPointer("go"),
		ExitCode: intPointer(0),
		Encoding: stringPointer("base64"),
		Content:  stringPointer(base64.StdEncoding.EncodeToString(make([]byte, MaxContentBytes+1))),
		BudgetMS: uint32Pointer(250),
	}
	if _, message := decodeRequest(params); message != "decoded content exceeds 16 MiB" {
		t.Fatalf("oversized decoded content message = %q", message)
	}
}

func TestServeRejectsInvalidJSONAndInvalidDependencies(t *testing.T) {
	optimizer := OptimizerFunc(func(Request) Action { return Pass() })
	if err := Serve(testIdentity, nil, strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("nil optimizer was accepted")
	}
	if err := Serve(testIdentity, optimizer, nil, io.Discard); err == nil {
		t.Fatal("nil input was accepted")
	}
	if err := Serve(testIdentity, optimizer, strings.NewReader(""), nil); err == nil {
		t.Fatal("nil output was accepted")
	}
	if err := Serve(testIdentity, optimizer, strings.NewReader("Content-Length: 1\r\n\r\n{"), io.Discard); err == nil || !strings.Contains(err.Error(), "invalid TSPP JSON") {
		t.Fatalf("invalid JSON error = %v", err)
	}
}

func TestRunWithStreamsKeepsProtocolAndDiagnosticsSeparated(t *testing.T) {
	optimizer := OptimizerFunc(func(Request) Action { return Pass() })
	var output, diagnostics bytes.Buffer
	runWithStreams(
		testIdentity,
		optimizer,
		strings.NewReader("Content-Length: 1\r\n\r\n{"),
		&output,
		&diagnostics,
	)
	if output.Len() != 0 {
		t.Fatalf("protocol output contains diagnostics: %q", output.String())
	}
	var record map[string]any
	if err := json.Unmarshal(diagnostics.Bytes(), &record); err != nil {
		t.Fatalf("diagnostic is not JSON: %v", err)
	}
	if record["level"] != "error" || record["source"] != "tokensaver-plugin-sdk" {
		t.Fatalf("diagnostic record = %#v", record)
	}

	output.Reset()
	diagnostics.Reset()
	runWithStreams(
		testIdentity,
		optimizer,
		bytes.NewReader(framed(t, map[string]any{"jsonrpc": "2.0", "method": "shutdown"})),
		&output,
		&diagnostics,
	)
	if output.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatalf("clean shutdown wrote output=%q diagnostics=%q", output.String(), diagnostics.String())
	}
	failingDiagnostics := &failWriter{failAtCall: 1}
	runWithStreams(
		testIdentity,
		optimizer,
		strings.NewReader("Content-Length: 1\r\n\r\n{"),
		io.Discard,
		failingDiagnostics,
	)
	if failingDiagnostics.calls < 2 {
		t.Fatal("structured diagnostic failure did not attempt the static JSON fallback")
	}
}

type failWriter struct {
	calls      int
	failAtCall int
	zeroAtCall int
	flushError bool
}

func (w *failWriter) Write(payload []byte) (int, error) {
	w.calls++
	if w.calls == w.failAtCall {
		return 0, errors.New("synthetic write failure")
	}
	if w.calls == w.zeroAtCall {
		return 0, nil
	}
	return len(payload), nil
}

func (w *failWriter) Flush() error {
	if w.flushError {
		return errors.New("synthetic flush failure")
	}
	return nil
}

func TestFrameWriterReportsSerializationWriteAndFlushFailures(t *testing.T) {
	if err := writeFrame(io.Discard, func() {}); err == nil || !strings.Contains(err.Error(), "serialize") {
		t.Fatalf("serialization error = %v", err)
	}
	if err := writeFrame(io.Discard, strings.Repeat("x", maxFrameBytes)); !errors.Is(err, ErrInvalidContentLength) {
		t.Fatalf("oversized response error = %v", err)
	}
	for _, writer := range []*failWriter{
		{failAtCall: 1},
		{failAtCall: 2},
		{zeroAtCall: 2},
		{flushError: true},
	} {
		if err := writeFrame(writer, map[string]any{"ok": true}); err == nil {
			t.Fatalf("writer %#v unexpectedly succeeded", writer)
		}
	}
}

func TestJSONRPCVersionAndUnknownMethodReturnProtocolErrors(t *testing.T) {
	input := framed(t, map[string]any{"jsonrpc": "1.0", "id": 1, "method": "initialize"})
	input = append(input, framed(t, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "future/method"})...)
	var output bytes.Buffer
	if err := Serve(testIdentity, OptimizerFunc(func(Request) Action { return Pass() }), bytes.NewReader(input), &output); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	responses := responseValues(t, output.Bytes())
	if got := responses[0]["error"].(map[string]any)["code"]; got != float64(-32600) {
		t.Fatalf("JSON-RPC version error = %v", got)
	}
	if got := responses[1]["error"].(map[string]any)["code"]; got != float64(-32601) {
		t.Fatalf("unknown method error = %v", got)
	}
}

func TestIndependentServersAreConcurrentAndDeterministic(t *testing.T) {
	const workers = 16
	optimizer := OptimizerFunc(func(request Request) Action {
		action, err := Optimized("safe:" + request.Text())
		if err != nil {
			return Pass()
		}
		return action
	})
	var wait sync.WaitGroup
	errs := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			var output bytes.Buffer
			if err := Serve(testIdentity, optimizer, bytes.NewReader(requestStream(t, "test", []byte("raw"))), &output); err != nil {
				errs <- err
				return
			}
			responses := responseValues(t, output.Bytes())
			if len(responses) != 2 || responses[1]["result"].(map[string]any)["action"] != "optimize" {
				errs <- errors.New("unexpected concurrent response")
			}
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestFrameReaderRejectsInvalidAndUnboundedHeaders(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{"zero length", "Content-Length: 0\r\n\r\n", ErrInvalidContentLength},
		{"oversize length", "Content-Length: 25165825\r\n\r\n", ErrInvalidContentLength},
		{"malformed header", "Broken\r\n\r\n", ErrMalformedHeader},
		{"header too large", strings.Repeat("x", maxHeaderBytes+1), ErrHeaderTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := bufio.NewReaderSize(strings.NewReader(test.input), maxHeaderBytes+1)
			if _, _, err := readFrame(reader); !errors.Is(err, test.want) {
				t.Fatalf("readFrame error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestFrameReaderBoundsHeaderCount(t *testing.T) {
	input := strings.Repeat("X-Test: value\r\n", maxHeaders+1) + "\r\n"
	reader := bufio.NewReaderSize(strings.NewReader(input), maxHeaderBytes+1)
	if _, _, err := readFrame(reader); !errors.Is(err, ErrTooManyHeaders) {
		t.Fatalf("readFrame error = %v, want %v", err, ErrTooManyHeaders)
	}
}

func TestFrameReaderReportsMissingLengthInvalidLengthAndShortBody(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{"missing length", "X-Test: value\r\n\r\n", ErrMissingContentLength},
		{"non-numeric length", "Content-Length: nope\r\n\r\n", ErrInvalidContentLength},
		{"short body", "Content-Length: 5\r\n\r\nxx", io.ErrUnexpectedEOF},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := bufio.NewReaderSize(strings.NewReader(test.input), maxHeaderBytes+1)
			if _, _, err := readFrame(reader); err == nil || !errors.Is(err, test.want) {
				t.Fatalf("readFrame error = %v, want %v", err, test.want)
			}
		})
	}
}

func requestStream(t *testing.T, kind string, content []byte) []byte {
	t.Helper()
	input := framed(t, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"apiVersion": 1, "host": "tokensaver", "budgetMs": 250},
	})
	input = append(input, framed(t, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "optimize",
		"params": map[string]any{
			"kind": kind, "program": "go", "exitCode": 1,
			"encoding": "base64", "content": base64.StdEncoding.EncodeToString(content), "budgetMs": 250,
		},
	})...)
	input = append(input, framed(t, map[string]any{"jsonrpc": "2.0", "method": "shutdown"})...)
	return input
}

func framed(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte("Content-Length: " + strconv.Itoa(len(payload)) + "\r\n\r\n")
	return append(frame, payload...)
}

func responseValues(t *testing.T, output []byte) []map[string]any {
	t.Helper()
	reader := bufio.NewReaderSize(bytes.NewReader(output), maxHeaderBytes+1)
	var values []map[string]any
	for {
		frame, ok, err := readFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return values
		}
		var value map[string]any
		if err := json.Unmarshal(frame, &value); err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
}

func stringPointer(value string) *string { return &value }
func intPointer(value int) *int          { return &value }
func uint32Pointer(value uint32) *uint32 { return &value }
