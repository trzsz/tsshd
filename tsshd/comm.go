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
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

var enableDebugLogging bool = false
var enableWarningLogging bool = false

var clientDebugFn func(int64, string)
var clientWarningFn func(string)

var debugMsgChan chan *debugMessage
var initDebugSenderOnce sync.Once

var warningMsgChan chan string
var initWarningSenderOnce sync.Once

var debugLogFile *os.File
var cleanupDebugLog atomic.Bool

func initDebugLogging() {
	enableDebugLogging = true

	var err error
	debugLogFile, err = os.CreateTemp("", fmt.Sprintf("tsshd_debug_%d_*.log", os.Getpid()))
	if err != nil {
		debug("create debug log file failed: %v", err)
	} else {
		debug("tsshd log path: %s", debugLogFile.Name())
		addOnExitFunc(func() {
			_ = debugLogFile.Close()
			if cleanupDebugLog.Load() {
				_ = os.Remove(debugLogFile.Name())
			}
		})
	}

	if path, err := os.Executable(); err == nil {
		debug("tsshd exe path: %s", path)
	}
	debug("tsshd version: %s", getTsshdVersion())
	debug("tsshd options: %s", strings.Join(os.Args[1:], " "))
}

func writeDebugLog(now *time.Time, msg string) {
	if debugLogFile == nil {
		return
	}

	_, _ = fmt.Fprintf(debugLogFile, "%s | %s\n", now.Format("15:04:05.000"), msg)
}

func debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}

	msg := fmt.Sprintf(format, a...)

	if clientDebugFn != nil {
		// should not reach here
		clientDebugFn(time.Now().UnixMilli(), fmt.Sprintf("[fix_me] %s", msg))
		return
	}

	initDebugSenderOnce.Do(func() {
		debugMsgChan = make(chan *debugMessage, 100)
		busClosingWG.Go(func() {
			for msg := range debugMsgChan {
				server := activeSshUdpServer.Load()
				for server == nil {
					time.Sleep(100 * time.Millisecond)
					server = activeSshUdpServer.Load()
				}
				if err := server.sendBusMessage("debug", msg); err != nil && debugLogFile != nil {
					now := time.Now()
					writeDebugLog(&now, fmt.Sprintf("send debug message failed: %v", err))
				}
			}
		})
	})

	now := time.Now()
	writeDebugLog(&now, msg)
	dbgMsg := &debugMessage{Msg: msg, Time: now.UnixMilli()}

	busClosingMu.Lock()
	defer busClosingMu.Unlock()

	if busClosing.Load() {
		return
	}

	select {
	case debugMsgChan <- dbgMsg:
	default:
	}
}

func warning(format string, a ...any) {
	if !enableWarningLogging {
		return
	}

	msg := fmt.Sprintf(format, a...)

	if clientWarningFn != nil {
		// should not reach here
		clientWarningFn(fmt.Sprintf("[fix_me] %s", msg))
		return
	}

	initWarningSenderOnce.Do(func() {
		warningMsgChan = make(chan string, 10)
		busClosingWG.Go(func() {
			for msg := range warningMsgChan {
				server := activeSshUdpServer.Load()
				for server == nil {
					time.Sleep(100 * time.Millisecond)
					server = activeSshUdpServer.Load()
				}
				if err := server.sendBusMessage("error", errorMessage{Msg: msg}); err != nil && debugLogFile != nil {
					now := time.Now()
					writeDebugLog(&now, fmt.Sprintf("send error message failed: %v", err))
				}
			}
		})
	})

	if debugLogFile != nil {
		now := time.Now()
		writeDebugLog(&now, fmt.Sprintf("warning: %s", msg))
	}

	busClosingMu.Lock()
	defer busClosingMu.Unlock()

	if busClosing.Load() {
		return
	}

	select {
	case warningMsgChan <- msg:
	default:
	}
}

func doWithTimeout[T any](task func() (T, error), timeout time.Duration) (T, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan struct {
		ret T
		err error
	}, 1)
	go func() {
		ret, err := task()
		done <- struct {
			ret T
			err error
		}{ret, err}
		close(done)
	}()
	select {
	case <-ctx.Done():
		var ret T
		return ret, fmt.Errorf("timeout exceeded %v", timeout)
	case res := <-done:
		return res.ret, res.err
	}
}

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	if errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	var qse *quic.StreamError
	if errors.As(err, &qse) && qse.ErrorCode == 0 {
		return true
	}
	if strings.Contains(err.Error(), "io: read/write on closed pipe") {
		return true
	}
	return false
}

type tsshdVersion [3]uint32

func parseTsshdVersion(ver string) (*tsshdVersion, error) {
	if ver == "" {
		return &tsshdVersion{}, nil
	}
	tokens := strings.Split(ver, ".")
	if len(tokens) != 3 {
		return nil, fmt.Errorf("invalid version format [%s]", ver)
	}
	var version tsshdVersion
	for i := range 3 {
		v, err := strconv.ParseUint(tokens[i], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid numeric part [%s] in version [%s]", tokens[i], ver)
		}
		version[i] = uint32(v)
	}
	return &version, nil
}

func (v *tsshdVersion) compare(ver *tsshdVersion) int {
	for i := range 3 {
		if v[i] < ver[i] {
			return -1
		}
		if v[i] > ver[i] {
			return 1
		}
	}
	return 0
}

type timeoutChecker struct {
	mutex                sync.Mutex
	closed               atomic.Bool
	closeChan            chan struct{}
	timeoutFlag          atomic.Bool
	lastAliveTime        atomic.Int64
	reconnectedCh        atomic.Pointer[chan struct{}]
	updateNowChan        chan struct{}
	updateTimeChan       chan int64
	timeoutEventChan     chan struct{}
	heartbeatTimeout     time.Duration
	timeoutCallbacks     []func()
	reconnectedCallbacks []func()
}

func newTimeoutChecker(heartbeatTimeout time.Duration) *timeoutChecker {
	tc := &timeoutChecker{
		closeChan:        make(chan struct{}),
		updateNowChan:    make(chan struct{}, 1),
		updateTimeChan:   make(chan int64, 2),
		timeoutEventChan: make(chan struct{}),
		heartbeatTimeout: heartbeatTimeout,
	}
	tc.lastAliveTime.Store(time.Now().UnixMilli())

	go tc.handleEvent()
	if tc.heartbeatTimeout > 0 {
		go tc.checkTimeout()
	}

	return tc
}

func (tc *timeoutChecker) isTimeout() bool {
	return tc.timeoutFlag.Load()
}

func (tc *timeoutChecker) waitUntilReconnected() error {
	return tc.waitReconnect(context.Background())
}

func (tc *timeoutChecker) waitReconnect(ctx context.Context) error {
	for {
		if !tc.isTimeout() {
			return nil
		}

		ch := tc.reconnectedCh.Load()
		for ch == nil {
			time.Sleep(10 * time.Millisecond)
			ch = tc.reconnectedCh.Load()
			if !tc.isTimeout() {
				return nil
			}
		}

		select {
		case <-*ch:
			continue
		case <-tc.closeChan:
			return fmt.Errorf("timeout closed")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (tc *timeoutChecker) getAliveTime() int64 {
	return tc.lastAliveTime.Load()
}

func (tc *timeoutChecker) updateNow() {
	select {
	case tc.updateNowChan <- struct{}{}:
	default:
	}
}

func (tc *timeoutChecker) updateTime(msec int64) {
	select {
	case tc.updateTimeChan <- msec:
	case <-tc.closeChan:
	}
}

func (tc *timeoutChecker) onTimeout(cb func()) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.timeoutCallbacks = append(tc.timeoutCallbacks, cb)
}

func (tc *timeoutChecker) onReconnected(cb func()) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.reconnectedCallbacks = append(tc.reconnectedCallbacks, cb)
}

func (tc *timeoutChecker) notifyTimeout() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	for _, cb := range tc.timeoutCallbacks {
		go cb()
	}
}

func (tc *timeoutChecker) notifyReconnected() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	for _, cb := range tc.reconnectedCallbacks {
		go cb()
	}
}

func (tc *timeoutChecker) checkTimeout() {
	for !tc.closed.Load() {
		sleepTime := time.Until(time.UnixMilli(tc.lastAliveTime.Load()).Add(tc.heartbeatTimeout))
		if sleepTime > 0 {
			select {
			case <-time.After(min(sleepTime, 10*time.Second)):
			case <-tc.closeChan:
				return
			}
			continue
		}

		// timeout event
		select {
		case tc.timeoutEventChan <- struct{}{}:
		case <-tc.closeChan:
			return
		}

		select {
		case <-time.After(min(tc.heartbeatTimeout, 10*time.Second)):
		case <-tc.closeChan:
			return
		}
	}
}

func (tc *timeoutChecker) handleEvent() {
	setReconnected := func() {
		if tc.timeoutFlag.Load() {
			tc.timeoutFlag.Store(false)
			if ch := tc.reconnectedCh.Swap(nil); ch != nil && *ch != nil {
				close(*ch)
			}
			go tc.notifyReconnected()
		}
	}

	for {
		select {
		case <-tc.updateNowChan:
			tc.lastAliveTime.Store(time.Now().UnixMilli())
			setReconnected()
		case msec := <-tc.updateTimeChan:
			if msec > tc.lastAliveTime.Load() {
				tc.lastAliveTime.Store(msec)
				if time.UnixMilli(msec).Add(tc.heartbeatTimeout).After(time.Now()) {
					setReconnected()
				}
			}
		case <-tc.timeoutEventChan:
			if time.UnixMilli(tc.lastAliveTime.Load()).Add(tc.heartbeatTimeout).Before(time.Now()) {
				if !tc.timeoutFlag.Load() {
					newCh := make(chan struct{})
					if oldCh := tc.reconnectedCh.Swap(&newCh); oldCh != nil && *oldCh != nil {
						close(*oldCh)
					}
					tc.timeoutFlag.Store(true)
					go tc.notifyTimeout()
				}
			}
		case <-tc.closeChan:
			return
		}
	}
}

func (tc *timeoutChecker) Close() {
	if !tc.closed.CompareAndSwap(false, true) {
		return
	}
	close(tc.closeChan)
}

const kAliveTimeCap = 5

type aliveTime struct {
	mutex sync.Mutex
	last  int
	buf   [kAliveTimeCap]int64
}

func (t *aliveTime) addMilli(milli int64) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.last = (t.last + 1) % kAliveTimeCap
	t.buf[t.last] = milli
}

func (r *aliveTime) latest() int64 {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.buf[r.last]
}

func (r *aliveTime) oldest() int64 {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.buf[(r.last+1)%kAliveTimeCap]
}

// newFileUnlinker returns a cleanup function that closes the provided closer
// and unlinks (removes) the specified file path. It ensures that the cleanup
// logic is executed only once, even if called multiple times (e.g., via both
// defer and a global exit hook).
func newFileUnlinker(path string, closer io.Closer) func() {
	var once sync.Once

	// Snapshot the file information at creation time to prevent
	// accidental unlinking if the file is replaced later.
	createdInfo, err := os.Stat(path)
	if err != nil {
		warning("stat created file [%s] failed: %v", path, err)
	}

	cleanup := func() {
		once.Do(func() {
			// 1. Close the resource first.
			if closer != nil {
				if err := closer.Close(); err != nil {
					debug("close resource for [%s] failed: %v", path, err)
				}
			}

			// 2. If we couldn't get the initial stat, it's unsafe to unlink.
			if createdInfo == nil {
				return
			}

			// 3. Verify the file identity (Inode check) before unlinking.
			currentInfo, err := os.Stat(path)
			if err != nil { // File might already be gone, which is fine.
				return
			}
			if !os.SameFile(createdInfo, currentInfo) {
				debug("file [%s] replaced since creation; skipping unlink", path)
				return
			}

			// 4. Perform the actual unlinking.
			if err := os.Remove(path); err != nil {
				warning("unlink file [%s] failed: %v", path, err)
				return
			}
			debug("unlink file [%s] successful", path)
		})
	}

	// Register the cleanup function to the global exit registry.
	addOnExitFunc(cleanup)

	// Return the cleanup function to be used with defer.
	return cleanup
}
