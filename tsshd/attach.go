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
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var attachMutex sync.Mutex

type replaceableStream struct {
	mu     sync.Mutex
	cond   *sync.Cond
	stream Stream
	closed bool
}

func newReplaceableStream(s Stream) *replaceableStream {
	ss := &replaceableStream{stream: s}
	ss.cond = sync.NewCond(&ss.mu)
	return ss
}

// swap replaces internal stream.
// If permanently closed, new stream is closed immediately.
func (s *replaceableStream) swap(newStream Stream) {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()
		if newStream != nil {
			_ = newStream.Close()
		}
		return
	}

	oldStream := s.stream
	s.stream = newStream

	s.cond.Broadcast()
	s.mu.Unlock()

	if oldStream != nil {
		_ = oldStream.Close()
	}
}

func (s *replaceableStream) do(fn func(Stream) error) error {
	for {
		s.mu.Lock()

		for s.stream == nil && !s.closed {
			s.cond.Wait()
		}

		if s.closed {
			s.mu.Unlock()
			return io.EOF
		}

		cur := s.stream
		s.mu.Unlock()

		// do executes operation on the active stream and retries if the stream is replaced
		err := fn(cur)

		s.mu.Lock()
		switched := s.stream != cur
		s.mu.Unlock()

		if switched {
			continue
		}

		return err
	}
}

func (s *replaceableStream) Close() error {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()
		return io.EOF
	}

	s.closed = true
	oldStream := s.stream
	s.stream = nil

	s.cond.Broadcast()
	s.mu.Unlock()

	if oldStream != nil {
		return oldStream.Close()
	}
	return nil
}

func (s *replaceableStream) Read(buf []byte) (int, error) {
	var n int
	err := s.do(func(st Stream) error {
		var err error
		n, err = st.Read(buf)
		return err
	})
	return n, err
}

func (s *replaceableStream) Write(buf []byte) (int, error) {
	var n int
	err := s.do(func(st Stream) error {
		var err error
		n, err = st.Write(buf)
		return err
	})
	return n, err
}

func (s *replaceableStream) CloseRead() error {
	return s.do(func(st Stream) error {
		return st.CloseRead()
	})
}

func (s *replaceableStream) CloseWrite() error {
	return s.do(func(st Stream) error {
		return st.CloseWrite()
	})
}

func (s *replaceableStream) SetDeadline(t time.Time) error {
	return s.do(func(st Stream) error {
		return st.SetDeadline(t)
	})
}

func (s *replaceableStream) SetReadDeadline(t time.Time) error {
	return s.do(func(st Stream) error {
		return st.SetReadDeadline(t)
	})
}

func (s *replaceableStream) SetWriteDeadline(t time.Time) error {
	return s.do(func(st Stream) error {
		return st.SetWriteDeadline(t)
	})
}

func (s *replaceableStream) LocalAddr() net.Addr {
	s.mu.Lock()
	cur := s.stream
	s.mu.Unlock()

	if cur == nil {
		return nil
	}
	return cur.LocalAddr()
}

func (s *replaceableStream) RemoteAddr() net.Addr {
	s.mu.Lock()
	cur := s.stream
	s.mu.Unlock()

	if cur == nil {
		return nil
	}
	return cur.RemoteAddr()
}

type replaceableTimeoutChecker struct {
	mu        sync.Mutex
	cancel    chan struct{}
	checker   *timeoutChecker
	gen       uint64
	callbacks []func()
}

func newReplaceableTimeoutChecker(checker *timeoutChecker) *replaceableTimeoutChecker {
	return &replaceableTimeoutChecker{checker: checker, cancel: make(chan struct{})}
}

func (c *replaceableTimeoutChecker) swap(newChecker *timeoutChecker) {
	c.mu.Lock()
	defer c.mu.Unlock()

	close(c.cancel)
	c.cancel = make(chan struct{})

	oldChecker := c.checker
	c.checker = newChecker

	c.gen++

	if newChecker == nil {
		return
	}

	if oldChecker == nil && !newChecker.isTimeout() {
		for _, cb := range c.callbacks {
			go cb()
		}
	}

	for _, cb := range c.callbacks {
		newChecker.onReconnected(c.wrapCallback(cb, c.gen))
	}
}

func (c *replaceableTimeoutChecker) isTimeout() bool {
	c.mu.Lock()
	checker := c.checker
	c.mu.Unlock()

	if checker == nil {
		return true
	}

	return checker.isTimeout()
}

func (c *replaceableTimeoutChecker) waitUntilReconnected() error {
	for {
		c.mu.Lock()
		cancel, checker := c.cancel, c.checker
		c.mu.Unlock()

		if checker == nil {
			<-cancel
			continue
		}

		if !checker.isTimeout() {
			return nil
		}

		errCh := make(chan error, 1)

		go func() {
			defer close(errCh)
			errCh <- checker.waitUntilReconnected()
		}()

		select {
		case err := <-errCh:
			c.mu.Lock()
			if c.checker == checker {
				c.mu.Unlock()
				return err
			}
			c.mu.Unlock()
		case <-cancel:
		}
	}
}

func (c *replaceableTimeoutChecker) onReconnected(cb func()) {
	c.mu.Lock()
	checker, gen := c.checker, c.gen
	c.callbacks = append(c.callbacks, cb)
	c.mu.Unlock()

	if checker != nil {
		wrapper := c.wrapCallback(cb, gen)
		checker.onReconnected(wrapper)
	}
}

func (c *replaceableTimeoutChecker) wrapCallback(cb func(), gen uint64) func() {
	return func() {
		c.mu.Lock()
		if c.gen != gen {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		cb()
	}
}

type discardStream struct{}

func (d *discardStream) Read(p []byte) (int, error)         { return 0, io.EOF }
func (d *discardStream) Write(p []byte) (int, error)        { return len(p), nil }
func (d *discardStream) Close() error                       { return nil }
func (d *discardStream) LocalAddr() net.Addr                { return nil }
func (d *discardStream) RemoteAddr() net.Addr               { return nil }
func (d *discardStream) SetDeadline(t time.Time) error      { return nil }
func (d *discardStream) SetReadDeadline(t time.Time) error  { return nil }
func (d *discardStream) SetWriteDeadline(t time.Time) error { return nil }
func (d *discardStream) CloseRead() error                   { return nil }
func (d *discardStream) CloseWrite() error                  { return nil }

func (s *sshUdpServer) attachSession(stream Stream, msg *startMessage) (*sessionContext, error) {
	if !s.args.Attachable {
		return nil, fmt.Errorf("attach is not allowed: tsshd was not started with --attachable")
	}

	sessionMutex.Lock()
	sess, ok := sessionMap[msg.ID]
	sessionMutex.Unlock()

	if !ok {
		return nil, fmt.Errorf("session not found")
	}

	if sess.closed.Load() {
		return nil, fmt.Errorf("session is closed")
	}

	attachMutex.Lock()
	defer attachMutex.Unlock()

	if server := activeSshUdpServer.Load(); server != s {
		return nil, fmt.Errorf("server is no longer active")
	}

	if sess.server.Load() != nil {
		return nil, fmt.Errorf("session already attached")
	}
	if sess.ioStream == nil {
		return nil, fmt.Errorf("invalid session state: i/o stream is nil")
	}
	if sess.errStream == nil {
		return nil, fmt.Errorf("invalid session state: err stream is nil")
	}

	if err := sendSuccess(stream); err != nil { // ack ok
		return nil, fmt.Errorf("ack ok failed: %v", err)
	}

	// The server reference must be updated before replacing the I/O stream,
	// since incoming data may immediately require the server instance.
	sess.server.Store(s)

	sess.ioStream.swap(stream)

	var errStream Stream
	if es := s.getStderrStream(msg.ErrID); es != nil {
		errStream = es
	} else {
		errStream = &discardStream{}
	}
	sess.errStream.swap(errStream)

	// The client checker is updated after stream setup to ensure streams
	// are ready when the client checker reports the client reconnected.
	sess.clientChecker.swap(s.clientChecker)

	if sess.pty != nil {
		if msg.Cols > 0 && msg.Rows > 0 {
			sess.cols, sess.rows = msg.Cols, msg.Rows
		}
		// redraw screen
		_ = sess.SetSize(sess.cols, sess.rows, true)
	}

	debug("session [%d] attached by client [%x]", msg.ID, s.client.proxyAddr.clientID)

	return sess, nil
}

func (s *sshUdpServer) detachAllSessions() {
	if !s.args.Attachable {
		return
	}

	sessionMutex.Lock()
	var sessions []*sessionContext
	for _, session := range sessionMap {
		sessions = append(sessions, session)
	}
	sessionMutex.Unlock()

	for _, sess := range sessions {
		// detach in the reverse order of attach
		sess.clientChecker.swap(nil)
		if sess.errStream != nil {
			sess.errStream.swap(nil)
		}
		if sess.ioStream != nil {
			sess.ioStream.swap(nil)
		}
		sess.server.Store(nil)

		sess.waitMutex.Lock()
		if cancel := sess.waitCancel; cancel != nil {
			close(cancel)
		}
		sess.waitCancel = nil
		sess.waitMutex.Unlock()

		debug("session [%d] detached by client [%x]", sess.id, s.client.proxyAddr.clientID)
	}
}
