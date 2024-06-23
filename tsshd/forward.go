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
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/xtaci/kcp-go/v5"
)

var acceptMutex sync.Mutex
var acceptID atomic.Uint64
var acceptMap = make(map[uint64]net.Conn)

func handleDialEvent(session *kcp.UDPSession) {
	var msg DialMessage
	if err := RecvMessage(session, &msg); err != nil {
		SendError(session, fmt.Errorf("recv dial message failed: %v", err))
		return
	}

	var err error
	var conn net.Conn
	if msg.Timeout > 0 {
		conn, err = net.DialTimeout(msg.Network, msg.Addr, msg.Timeout)
	} else {
		conn, err = net.Dial(msg.Network, msg.Addr)
	}
	if err != nil {
		SendError(session, fmt.Errorf("dial %s [%s] failed: %v", msg.Network, msg.Addr, err))
		return
	}

	defer conn.Close()

	if err := SendSuccess(session); err != nil { // ack ok
		trySendErrorMessage("dial ack ok failed: %v", err)
		return
	}

	forwardConnection(session, conn)
}

func handleListenEvent(session *kcp.UDPSession) {
	var msg ListenMessage
	if err := RecvMessage(session, &msg); err != nil {
		SendError(session, fmt.Errorf("recv listen message failed: %v", err))
		return
	}

	listener, err := net.Listen(msg.Network, msg.Addr)
	if err != nil {
		SendError(session, fmt.Errorf("listen on %s [%s] failed: %v", msg.Network, msg.Addr, err))
		return
	}

	defer listener.Close()

	if err := SendSuccess(session); err != nil { // ack ok
		trySendErrorMessage("listen ack ok failed: %v", err)
		return
	}

	for {
		conn, err := listener.Accept()
		if err == io.EOF {
			break
		}
		if err != nil {
			trySendErrorMessage("listener %s [%s] accept failed: %v", msg.Network, msg.Addr, err)
			continue
		}
		acceptMutex.Lock()
		id := acceptID.Add(1) - 1
		acceptMap[id] = conn
		if err := SendMessage(session, AcceptMessage{id}); err != nil {
			acceptMutex.Unlock()
			trySendErrorMessage("send accept message failed: %v", err)
			return
		}
		acceptMutex.Unlock()
	}
}

func handleAcceptEvent(session *kcp.UDPSession) {
	var msg AcceptMessage
	if err := RecvMessage(session, &msg); err != nil {
		SendError(session, fmt.Errorf("recv accept message failed: %v", err))
		return
	}

	acceptMutex.Lock()
	defer acceptMutex.Unlock()

	conn, ok := acceptMap[msg.ID]
	if !ok {
		SendError(session, fmt.Errorf("invalid accept id: %d", msg.ID))
		return
	}

	delete(acceptMap, msg.ID)
	defer conn.Close()

	if err := SendSuccess(session); err != nil { // ack ok
		trySendErrorMessage("accept ack ok failed: %v", err)
		return
	}

	forwardConnection(session, conn)
}

func forwardConnection(session *kcp.UDPSession, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		_, _ = io.Copy(conn, session)
		wg.Done()
	}()
	go func() {
		_, _ = io.Copy(session, conn)
		wg.Done()
	}()
	wg.Wait()
}
