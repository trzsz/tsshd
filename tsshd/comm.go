/*
MIT License

Copyright (c) 2024-2025 The Trzsz SSH Authors.

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
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type globalSettings struct {
	keepPendingInput atomic.Bool
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
		go func() {
			for busStream == nil {
				time.Sleep(10 * time.Millisecond)
			}
			for msg := range debugMsgChan {
				_ = sendBusMessage("debug", msg)
			}
		}()
	})

	dbgMsg := &debugMessage{Msg: msg, Time: time.Now().UnixMilli()}
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
		go func() {
			for busStream == nil {
				time.Sleep(10 * time.Millisecond)
			}
			for msg := range warningMsgChan {
				_ = sendBusMessage("error", errorMessage{Msg: msg})
			}
		}()
	})

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

type timeoutChecker struct {
	timeoutMilli    int64
	timeoutCallback func(bool)
	timeoutFlag     atomic.Bool
	lastAliveTime   atomic.Int64
}

func newTimeoutChecker(timeout time.Duration, callback func(bool)) *timeoutChecker {
	tc := &timeoutChecker{timeoutMilli: int64(timeout / time.Millisecond), timeoutCallback: callback}
	tc.lastAliveTime.Store(time.Now().UnixMilli())
	if tc.timeoutMilli > 0 {
		go tc.checkTimeout()
	}
	return tc
}

func (tc *timeoutChecker) isTimeout() bool {
	return tc.timeoutFlag.Load()
}

func (tc *timeoutChecker) getAliveTime() int64 {
	return tc.lastAliveTime.Load()
}

func (tc *timeoutChecker) updateTime(ms int64) {
	tc.lastAliveTime.Store(ms)
	if tc.timeoutFlag.Load() {
		tc.timeoutFlag.Store(false)
		tc.timeoutCallback(tc.timeoutFlag.Load())
	}
}

func (tc *timeoutChecker) checkTimeout() {
	for {
		sleepTime := tc.lastAliveTime.Load() + tc.timeoutMilli - time.Now().UnixMilli()
		if sleepTime > 0 {
			time.Sleep(time.Duration(sleepTime) * time.Millisecond)
			continue
		}
		// timeout
		if !tc.timeoutFlag.Load() {
			tc.timeoutFlag.Store(true)
			tc.timeoutCallback(tc.timeoutFlag.Load())
			time.Sleep(10 * time.Millisecond)
			if tc.timeoutFlag.Load() && tc.lastAliveTime.Load()+tc.timeoutMilli > time.Now().UnixMilli() {
				tc.timeoutFlag.Store(false)
				tc.timeoutCallback(tc.timeoutFlag.Load())
				continue
			}
		}
		time.Sleep(time.Duration(tc.timeoutMilli) * time.Millisecond)
	}
}
