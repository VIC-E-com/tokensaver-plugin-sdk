package tokensaverplugin

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	apiVersion     = 1
	maxFrameBytes  = 24 << 20
	maxHeaderBytes = 8 << 10
	maxHeaders     = 32
)

var (
	ErrMalformedHeader      = errors.New("malformed TSPP frame header")
	ErrMissingContentLength = errors.New("TSPP frame has no Content-Length")
	ErrInvalidContentLength = errors.New("invalid TSPP Content-Length")
	ErrTooManyHeaders       = errors.New("too many TSPP frame headers")
	ErrHeaderTooLarge       = errors.New("TSPP frame headers exceed the size limit")
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type initializeParams struct {
	APIVersion *uint32 `json:"apiVersion"`
	Host       *string `json:"host"`
	BudgetMS   *uint32 `json:"budgetMs"`
}

type optimizeParams struct {
	Kind     *string `json:"kind"`
	Program  *string `json:"program"`
	ExitCode *int    `json:"exitCode"`
	Encoding *string `json:"encoding"`
	Content  *string `json:"content"`
	BudgetMS *uint32 `json:"budgetMs"`
}

// Serve handles TSPP v1 on caller-provided streams. It is public so plugin
// tests and workbenches can exercise exactly the runtime used by Run.
//
// Unknown additive JSON fields are accepted within v1. Framing, decoded
// content, and response sizes remain strictly bounded.
func Serve(identity Identity, optimizer Optimizer, input io.Reader, output io.Writer) error {
	if optimizer == nil {
		return errors.New("tokensaver plugin optimizer is nil")
	}
	if input == nil {
		return errors.New("tokensaver plugin input is nil")
	}
	if output == nil {
		return errors.New("tokensaver plugin output is nil")
	}
	reader := bufio.NewReaderSize(input, maxHeaderBytes+1)
	initialized := false
	for {
		frame, ok, err := readFrame(reader)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		var request rpcRequest
		if err := json.Unmarshal(frame, &request); err != nil {
			return fmt.Errorf("invalid TSPP JSON: %w", err)
		}
		if request.JSONRPC != "2.0" {
			if err := writeError(output, request.ID, -32600, "jsonrpc must be 2.0"); err != nil {
				return err
			}
			continue
		}
		switch request.Method {
		case "initialize":
			params, valid := decodeInitializeParams(request.Params)
			if !valid {
				if err := writeError(output, request.ID, -32602, "invalid initialize params"); err != nil {
					return err
				}
				continue
			}
			if *params.APIVersion != apiVersion {
				if err := writeError(output, request.ID, -32602, "unsupported apiVersion"); err != nil {
					return err
				}
				continue
			}
			initialized = true
			if err := writeResult(output, request.ID, map[string]any{
				"apiVersion": apiVersion,
				"pluginId":   identity.PluginID,
				"version":    identity.Version,
			}); err != nil {
				return err
			}
		case "optimize":
			if !initialized {
				if err := writeError(output, request.ID, -32002, "plugin is not initialized"); err != nil {
					return err
				}
				continue
			}
			params, valid := decodeOptimizeParams(request.Params)
			if !valid {
				if err := writeError(output, request.ID, -32602, "invalid optimize params"); err != nil {
					return err
				}
				continue
			}
			decoded, message := decodeRequest(params)
			if message != "" {
				if err := writeError(output, request.ID, -32602, message); err != nil {
					return err
				}
				continue
			}
			action, panicked := callOptimizer(optimizer, decoded)
			if panicked {
				if err := writeError(output, request.ID, -32603, "optimizer panicked"); err != nil {
					return err
				}
				continue
			}
			if err := writeAction(output, request.ID, action); err != nil {
				return err
			}
		case "shutdown":
			return nil
		default:
			if err := writeError(output, request.ID, -32601, "method not found"); err != nil {
				return err
			}
		}
	}
}

func decodeInitializeParams(raw json.RawMessage) (initializeParams, bool) {
	var params initializeParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return initializeParams{}, false
	}
	return params, params.APIVersion != nil && params.Host != nil && params.BudgetMS != nil
}

func decodeOptimizeParams(raw json.RawMessage) (optimizeParams, bool) {
	var params optimizeParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return optimizeParams{}, false
	}
	valid := params.Kind != nil && params.Program != nil && params.ExitCode != nil &&
		params.Encoding != nil && params.Content != nil && params.BudgetMS != nil
	return params, valid
}

func decodeRequest(params optimizeParams) (Request, string) {
	if *params.Encoding != "base64" {
		return Request{}, "encoding must be base64"
	}
	content, err := base64.StdEncoding.DecodeString(*params.Content)
	if err != nil {
		return Request{}, "content is not valid base64"
	}
	if len(content) > MaxContentBytes {
		return Request{}, "decoded content exceeds 16 MiB"
	}
	for _, value := range content {
		if value == 0 {
			return Request{}, "decoded content contains NUL bytes"
		}
	}
	if !utf8.Valid(content) {
		return Request{}, "decoded content is not UTF-8"
	}
	return Request{
		kind:     Kind(*params.Kind),
		program:  *params.Program,
		exitCode: *params.ExitCode,
		text:     string(content),
		budgetMS: *params.BudgetMS,
	}, ""
}

func callOptimizer(optimizer Optimizer, request Request) (action Action, panicked bool) {
	defer func() {
		if recover() != nil {
			action = Pass()
			panicked = true
		}
	}()
	return optimizer.Optimize(request), false
}

func writeAction(writer io.Writer, id json.RawMessage, action Action) error {
	switch action.kind {
	case actionPass:
		return writeResult(writer, id, map[string]any{"action": "pass"})
	case actionOptimize:
		content := action.content
		if content == "" || len(content) > MaxContentBytes || !utf8.ValidString(content) || strings.IndexByte(content, 0) >= 0 {
			return writeError(writer, id, -32603, "unsafe optimized content")
		}
		return writeResult(writer, id, map[string]any{
			"action":  "optimize",
			"content": base64.StdEncoding.EncodeToString([]byte(content)),
		})
	default:
		return writeError(writer, id, -32603, "unsafe optimized content")
	}
}

func writeResult(writer io.Writer, id json.RawMessage, result any) error {
	return writeFrame(writer, rpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func writeError(writer io.Writer, id json.RawMessage, code int, message string) error {
	return writeFrame(writer, rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	})
}

func writeFrame(writer io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("serialize TSPP response: %w", err)
	}
	if len(payload) == 0 || len(payload) > maxFrameBytes {
		return ErrInvalidContentLength
	}
	if _, err := fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(payload)); err != nil {
		return fmt.Errorf("write TSPP frame header: %w", err)
	}
	if err := writeAll(writer, payload); err != nil {
		return fmt.Errorf("write TSPP frame body: %w", err)
	}
	if flusher, ok := writer.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			return fmt.Errorf("flush TSPP response: %w", err)
		}
	}
	return nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if written > 0 {
			payload = payload[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readFrame(reader *bufio.Reader) ([]byte, bool, error) {
	var contentLength int
	hasContentLength := false
	headerBytes := 0
	for headerCount := 0; headerCount <= maxHeaders; headerCount++ {
		line, err := reader.ReadString('\n')
		headerBytes += len(line)
		if headerBytes > maxHeaderBytes || errors.Is(err, bufio.ErrBufferFull) {
			return nil, false, ErrHeaderTooLarge
		}
		if errors.Is(err, io.EOF) && len(line) == 0 {
			if headerCount == 0 {
				return nil, false, nil
			}
			return nil, false, ErrMissingContentLength
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, false, fmt.Errorf("read TSPP frame header: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if hasContentLength {
				frame := make([]byte, contentLength)
				if _, err := io.ReadFull(reader, frame); err != nil {
					return nil, false, fmt.Errorf("read TSPP frame body: %w", err)
				}
				return frame, true, nil
			}
		} else {
			name, value, found := strings.Cut(line, ":")
			if !found {
				return nil, false, ErrMalformedHeader
			}
			if strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
				length, parseErr := strconv.Atoi(strings.TrimSpace(value))
				if parseErr != nil || length <= 0 || length > maxFrameBytes {
					return nil, false, ErrInvalidContentLength
				}
				contentLength = length
				hasContentLength = true
			}
		}
		if errors.Is(err, io.EOF) {
			return nil, false, ErrMissingContentLength
		}
	}
	return nil, false, ErrTooManyHeaders
}
