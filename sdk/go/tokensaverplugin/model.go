// Package tokensaverplugin implements the public TokenSaver Plugin Protocol
// (TSPP) v1 runtime for Go optimizer plugins.
//
// The package contains protocol plumbing only. Optimization behavior belongs
// to each plugin, and the TokenSaver host independently verifies every result.
package tokensaverplugin

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// MaxContentBytes is the largest decoded input or optimized output accepted by
// the TSPP v1 SDK.
const MaxContentBytes = 16 << 20

// Kind identifies the host-classified command-output category.
type Kind string

const (
	KindTest   Kind = "test"
	KindBuild  Kind = "build"
	KindLint   Kind = "lint"
	KindStatus Kind = "status"
	KindLog    Kind = "log"
)

// Identity is compiled into a plugin and must match plugin.json. API version
// is owned by the SDK and is intentionally not configurable here.
type Identity struct {
	PluginID string
	Version  string
}

// Request is a host-validated command-output optimization request. Its fields
// are immutable so plugin code cannot accidentally corrupt protocol state.
type Request struct {
	kind     Kind
	program  string
	exitCode int
	text     string
	budgetMS uint32
}

// Kind returns the host-classified output kind.
func (r Request) Kind() Kind { return r.kind }

// Program returns only the executable basename measured by the host. TSPP v1
// never discloses command arguments to an optimizer plugin.
func (r Request) Program() string { return r.program }

// ExitCode returns the original command exit code.
func (r Request) ExitCode() int { return r.exitCode }

// Text returns the decoded UTF-8 command output.
func (r Request) Text() string { return r.text }

// BudgetMS returns the advisory request budget. The host enforces its own
// deadline independently.
func (r Request) BudgetMS() uint32 { return r.budgetMS }

// Optimizer is the only behavior a Go optimizer plugin implements.
type Optimizer interface {
	Optimize(Request) Action
}

// OptimizerFunc adapts a function into an Optimizer.
type OptimizerFunc func(Request) Action

// Optimize calls f(request).
func (f OptimizerFunc) Optimize(request Request) Action { return f(request) }

type actionKind uint8

const (
	actionPass actionKind = iota
	actionOptimize
)

// Action is a plugin proposal. The zero value safely means pass.
//
// TokenSaver independently measures and validates optimized content before it
// can be displayed.
type Action struct {
	kind    actionKind
	content string
}

// Pass returns a safe no-change action.
func Pass() Action { return Action{} }

var (
	// ErrEmptyContent reports an empty optimization proposal.
	ErrEmptyContent = errors.New("optimized content cannot be empty")
	// ErrNULContent reports an optimization proposal containing a NUL byte.
	ErrNULContent = errors.New("optimized content cannot contain NUL bytes")
	// ErrInvalidUTF8 reports an optimization proposal that is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("optimized content must be valid UTF-8")
	// ErrContentTooLarge reports an optimization proposal over MaxContentBytes.
	ErrContentTooLarge = errors.New("optimized content exceeds the size limit")
)

// Optimized constructs a safe UTF-8 optimization proposal. Go strings are
// valid byte containers, so protocol emission rechecks UTF-8 validity as well.
func Optimized(content string) (Action, error) {
	if content == "" {
		return Action{}, ErrEmptyContent
	}
	if len(content) > MaxContentBytes {
		return Action{}, fmt.Errorf(
			"%w: got %d bytes, maximum is %d",
			ErrContentTooLarge,
			len(content),
			MaxContentBytes,
		)
	}
	if !utf8.ValidString(content) {
		return Action{}, ErrInvalidUTF8
	}
	for index := 0; index < len(content); index++ {
		if content[index] == 0 {
			return Action{}, ErrNULContent
		}
	}
	return Action{kind: actionOptimize, content: content}, nil
}
