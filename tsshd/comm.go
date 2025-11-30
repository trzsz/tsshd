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
	"time"
)

var enableDebugLogging bool = false
var enableWarningLogging bool = false

var clientDebug func(string, ...any)
var clientWarning func(string, ...any)

func debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}

	msg := fmt.Sprintf(format, a...)

	if clientDebug != nil {
		clientDebug("%s", msg)
	}

	_, _ = doWithTimeout(func() (int, error) {
		_ = sendBusMessage("debug", debugMessage{Msg: msg})
		return 0, nil
	}, 100*time.Millisecond)
}

func warning(format string, a ...any) {
	if !enableWarningLogging {
		return
	}

	msg := fmt.Sprintf(format, a...)

	if clientWarning != nil {
		clientWarning("%s", msg)
		return
	}

	go func() { _ = sendBusMessage("error", errorMessage{Msg: msg}) }()
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
