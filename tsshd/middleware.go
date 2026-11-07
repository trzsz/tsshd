/*
MIT License

Copyright (c) 2024-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tsshd

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
)

// sessionHandler is the callback invoked for each established session.
var sessionHandler Handler

// enableForwarding indicates whether SSH forwarding features are enabled.
var enableForwardings bool

// Session provides access to an SSH session and exposes methods for
// interacting with its underlying channel, including reading from stdin
// and writing to stdout/stderr.
//
// A session corresponds to either an interactive shell or an exec request.
// If Command() returns an empty slice, the client requested a shell.
// Otherwise, the session represents an exec request with the given arguments.
type Session interface {
	// Read reads up to len(data) bytes from the session's standard input.
	Read(data []byte) (int, error)

	// Write writes len(data) bytes to the session's standard output.
	Write(data []byte) (int, error)

	// Close closes the session and releases associated resources.
	Close() error

	// CloseWrite closes the standard output stream. After this call,
	// no more data can be written to stdout, but stdin may still be read.
	CloseWrite() error

	// Stderr returns a writer for the session's standard error stream.
	Stderr() io.WriteCloser

	// Environ returns a copy of the environment variables set by the client,
	// in the form "key=value".
	Environ() []string

	// Exit sends an exit status to the client and then closes the session.
	Exit(code int) error

	// Command returns the command parsed into arguments using POSIX shell rules.
	Command() []string

	// Subsystem returns the requested subsystem, if any.
	Subsystem() string

	// Pty returns the PTY configuration, a channel of window size changes,
	// and a boolean indicating whether a PTY was allocated.
	Pty() (PtyState, <-chan Window, bool)

	// Context returns the session's context. The returned context is always
	// non-nil and is canceled when the client quits or the session is closed.
	Context() context.Context
}

// Window represents the size of a PTY window.
type Window struct {
	// Width is the number of columns.
	Width int

	// Height is the number of rows.
	Height int
}

// PtyState holds the current state of a pseudo-terminal (PTY)
// for a session, including terminal type and window size.
//
// It reflects the active PTY properties rather than the
// original request parameters.
type PtyState struct {
	// Term is the value of the TERM environment variable.
	Term string

	// Window is the current window size of the PTY.
	Window Window
}

// Option represents a functional option for configuring the server.
type Option func() error

// Handler is a callback that handles an established session.
type Handler func(Session)

// Middleware is a function that takes an Handler and returns an Handler.
// Implementations should invoke the provided next handler.
type Middleware func(next Handler) Handler

// WithMiddleware composes the provided middleware chain into a single handler
// and sets it as the session handler.
//
// Middleware is applied in the order provided, but executed in reverse order.
// That is, the last middleware will be executed first.
func WithMiddleware(mw ...Middleware) Option {
	return func() error {
		h := func(Session) {}
		for _, m := range mw {
			h = m(h)
		}
		sessionHandler = h
		return nil
	}
}

// WithForwarding enables SSH forwarding features.
func WithForwardings() Option {
	return func() error {
		enableForwardings = true
		return nil
	}
}

type middlewareSession struct {
	ctx      context.Context
	cancel   context.CancelFunc
	pty      bool
	subs     string
	cmds     []string
	envs     []string
	ptyState PtyState
	stdin    io.ReadCloser
	stdout   io.WriteCloser
	stderr   io.WriteCloser
	sizeCh   chan Window
	waitCh   chan struct{}
	closed   atomic.Bool
	exitCode atomic.Pointer[int]
}

func newMiddlewareSession(msg *startMessage) *middlewareSession {
	ctx, cancel := context.WithCancel(context.Background())

	var cmds []string
	if !msg.Shell {
		cmds = append(cmds, msg.Name)
		cmds = append(cmds, msg.Args...)
	}

	return &middlewareSession{
		ctx:    ctx,
		cancel: cancel,
		pty:    msg.Pty,
		subs:   msg.Subs,
		cmds:   cmds,
		envs:   getEnvironments(msg),
		ptyState: PtyState{
			Term:   msg.Envs["TERM"],
			Window: Window{Width: msg.Cols, Height: msg.Rows},
		},
		sizeCh: make(chan Window, 10),
		waitCh: make(chan struct{}),
	}
}

func (s *middlewareSession) Read(data []byte) (int, error) {
	return s.stdin.Read(data)
}

func (s *middlewareSession) Write(data []byte) (int, error) {
	return s.stdout.Write(data)
}

func (s *middlewareSession) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	if s.cancel != nil {
		s.cancel()
	}

	if s.stderr != nil {
		_ = s.stderr.Close()
	}
	if s.stdout != nil {
		_ = s.stdout.Close()
	}
	if s.stdin != nil {
		_ = s.stdin.Close()
	}

	close(s.waitCh)
	return nil
}

func (s *middlewareSession) CloseWrite() error {
	return s.stdout.Close()
}

func (s *middlewareSession) Stderr() io.WriteCloser {
	return s.stderr
}

func (s *middlewareSession) Environ() []string {
	return s.envs
}

func (s *middlewareSession) Exit(code int) error {
	s.exitCode.CompareAndSwap(nil, &code)
	return s.Close()
}

func (s *middlewareSession) Command() []string {
	return s.cmds
}

func (s *middlewareSession) Subsystem() string {
	return s.subs
}

func (s *middlewareSession) Pty() (PtyState, <-chan Window, bool) {
	return s.ptyState, s.sizeCh, s.pty
}

func (s *middlewareSession) Context() context.Context {
	return s.ctx
}

func (s *middlewareSession) Wait() error {
	<-s.waitCh
	return nil
}

func (s *middlewareSession) Resize(cols, rows int) error {
	s.ptyState.Window.Width, s.ptyState.Window.Height = cols, rows
	// Drain old resize event if channel is full to ensure
	// the most recent size is always delivered.
	window := Window{Width: cols, Height: rows}
	select {
	case s.sizeCh <- window:
		return nil
	default:
		// Remove one old event
		select {
		case <-s.sizeCh:
		default:
		}
		// Try again
		select {
		case s.sizeCh <- window:
			return nil
		default:
			return errors.New("resize event dropped: channel is full")
		}
	}
}
