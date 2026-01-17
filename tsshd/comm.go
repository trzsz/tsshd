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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type globalSettings struct {
	keepPendingInput  atomic.Bool
	keepPendingOutput atomic.Bool
}

var globalSetting = &globalSettings{}

var enableDebugLogging bool = false
var enableWarningLogging bool = false

var clientDebug func(int64, string)
var clientWarningFunc func(string)

var debugMsgChan chan *debugMessage
var initDebugSenderOnce sync.Once

var warningMsgChan chan string
var initWarningSenderOnce sync.Once

func debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}

	msg := fmt.Sprintf(format, a...)

	if clientDebug != nil {
		// should not reach here
		clientDebug(time.Now().UnixMilli(), fmt.Sprintf("[fix_me] %s", msg))
		return
	}

	initDebugSenderOnce.Do(func() {
		debugMsgChan = make(chan *debugMessage, 100)
		busClosingWG.Go(func() {
			for !isBusStreamInited() {
				time.Sleep(10 * time.Millisecond)
			}
			for msg := range debugMsgChan {
				_ = sendBusMessage("debug", msg)
			}
		})
	})

	dbgMsg := &debugMessage{Msg: msg, Time: time.Now().UnixMilli()}

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

	if clientWarningFunc != nil {
		// should not reach here
		clientWarningFunc(fmt.Sprintf("[fix_me] %s", msg))
		return
	}

	initWarningSenderOnce.Do(func() {
		warningMsgChan = make(chan string, 10)
		busClosingWG.Go(func() {
			for !isBusStreamInited() {
				time.Sleep(10 * time.Millisecond)
			}
			for msg := range warningMsgChan {
				_ = sendBusMessage("error", errorMessage{Msg: msg})
			}
		})
	})

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

type timeoutChecker struct {
	mutex                sync.Mutex
	closed               atomic.Bool
	closeChan            chan struct{}
	timeoutFlag          atomic.Bool
	timeoutMilli         atomic.Int64
	lastAliveTime        atomic.Int64
	reconnectedCh        chan struct{}
	updateNowChan        chan struct{}
	updateTimeChan       chan int64
	timeoutEventChan     chan struct{}
	timeoutCallbacks     []func()
	reconnectedCallbacks []func()
}

func newTimeoutChecker(timeout time.Duration) *timeoutChecker {
	tc := &timeoutChecker{
		closeChan:        make(chan struct{}),
		reconnectedCh:    make(chan struct{}),
		updateNowChan:    make(chan struct{}, 1),
		updateTimeChan:   make(chan int64, 2),
		timeoutEventChan: make(chan struct{}),
	}
	tc.timeoutMilli.Store(int64(timeout / time.Millisecond))
	tc.lastAliveTime.Store(time.Now().UnixMilli())
	close(tc.reconnectedCh)

	go tc.handleEvent()
	if tc.timeoutMilli.Load() > 0 {
		go tc.checkTimeout()
	}

	return tc
}

func (tc *timeoutChecker) isTimeout() bool {
	return tc.timeoutFlag.Load()
}

func (tc *timeoutChecker) waitUntilReconnected() error {
	if !tc.isTimeout() {
		return nil
	}
	ch := tc.reconnectedCh
	select {
	case <-ch:
		return nil
	case <-tc.closeChan:
		return fmt.Errorf("timeout closed")
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
		sleepMilli := tc.lastAliveTime.Load() + tc.timeoutMilli.Load() - time.Now().UnixMilli()
		if sleepMilli > 0 {
			select {
			case <-time.After(min(time.Duration(sleepMilli)*time.Millisecond, 10*time.Second)):
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
		case <-time.After(min(time.Duration(tc.timeoutMilli.Load())*time.Millisecond, 10*time.Second)):
		case <-tc.closeChan:
			return
		}
	}
}

func (tc *timeoutChecker) handleEvent() {
	setReconnected := func() {
		if tc.timeoutFlag.Load() {
			tc.timeoutFlag.Store(false)
			close(tc.reconnectedCh)
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
				if msec+tc.timeoutMilli.Load() > time.Now().UnixMilli() {
					setReconnected()
				}
			}
		case <-tc.timeoutEventChan:
			if tc.lastAliveTime.Load()+tc.timeoutMilli.Load() <= time.Now().UnixMilli() {
				if !tc.timeoutFlag.Load() {
					tc.reconnectedCh = make(chan struct{})
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

const kAliveTimeCap = 10

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
