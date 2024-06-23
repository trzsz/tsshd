/*
MIT License

Copyright (c) 2024 The Trzsz SSH Authors.

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
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

var serving atomic.Bool

var exitChan = make(chan bool, 1)

func serve(listener *kcp.Listener) {
	defer listener.Close()

	go func() {
		// should be connected within 10 seconds
		time.Sleep(10 * time.Second)
		if !serving.Load() {
			exitChan <- true
		}
	}()

	go func() {
		for {
			session, err := listener.AcceptKCP()
			if err != nil {
				trySendErrorMessage("kcp accept failed: %v", err)
				return
			}
			go handleSession(session)
		}
	}()

	<-exitChan
}

func handleSession(session *kcp.UDPSession) {
	defer session.Close()

	session.SetNoDelay(1, 10, 2, 1)

	command, err := RecvCommand(session)
	if err != nil {
		SendError(session, fmt.Errorf("recv session command failed: %v", err))
		return
	}

	var handler func(*kcp.UDPSession)

	switch command {
	case "bus":
		handler = handleBusEvent
	case "session":
		handler = handleSessionEvent
	case "stderr":
		handler = handleStderrEvent
	case "dial":
		handler = handleDialEvent
	case "listen":
		handler = handleListenEvent
	case "accept":
		handler = handleAcceptEvent
	default:
		SendError(session, fmt.Errorf("unknown session command: %s", command))
		return
	}

	if err := SendSuccess(session); err != nil { // say hello
		trySendErrorMessage("tsshd say hello failed: %v", err)
		return
	}

	handler(session)
}
