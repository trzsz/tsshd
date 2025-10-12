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
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

var acceptMutex sync.Mutex
var acceptID atomic.Uint64
var acceptMap = make(map[uint64]net.Conn)

func handleDialEvent(stream net.Conn) {
	var msg DialMessage
	if err := RecvMessage(stream, &msg); err != nil {
		SendError(stream, fmt.Errorf("recv dial message failed: %v", err))
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
		SendError(stream, fmt.Errorf("dial %s [%s] failed: %v", msg.Network, msg.Addr, err))
		return
	}

	defer conn.Close()

	if err := SendSuccess(stream); err != nil { // ack ok
		trySendErrorMessage("dial ack ok failed: %v", err)
		return
	}

	forwardConnection(stream, conn)
}

func handleListenEvent(stream net.Conn) {
	var msg ListenMessage
	if err := RecvMessage(stream, &msg); err != nil {
		SendError(stream, fmt.Errorf("recv listen message failed: %v", err))
		return
	}

	listener, err := net.Listen(msg.Network, msg.Addr)
	if err != nil {
		SendError(stream, fmt.Errorf("listen on %s [%s] failed: %v", msg.Network, msg.Addr, err))
		return
	}

	onExitFuncs = append(onExitFuncs, func() {
		listener.Close()
		if msg.Network == "unix" {
			_ = os.Remove(msg.Addr)
		}
	})
	defer listener.Close()

	if err := SendSuccess(stream); err != nil { // ack ok
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
		id := addAcceptConn(conn)
		if err := SendMessage(stream, AcceptMessage{id}); err != nil {
			if conn := getAcceptConn(id); conn != nil {
				conn.Close()
			}
			trySendErrorMessage("send accept message failed: %v", err)
			return
		}
	}
}

func handleAcceptEvent(stream net.Conn) {
	var msg AcceptMessage
	if err := RecvMessage(stream, &msg); err != nil {
		SendError(stream, fmt.Errorf("recv accept message failed: %v", err))
		return
	}

	conn := getAcceptConn(msg.ID)
	if conn == nil {
		SendError(stream, fmt.Errorf("invalid accept id: %d", msg.ID))
		return
	}

	defer conn.Close()

	if err := SendSuccess(stream); err != nil { // ack ok
		trySendErrorMessage("accept ack ok failed: %v", err)
		return
	}

	forwardConnection(stream, conn)
}

func addAcceptConn(conn net.Conn) uint64 {
	acceptMutex.Lock()
	defer acceptMutex.Unlock()
	id := acceptID.Add(1) - 1
	acceptMap[id] = conn
	return id
}

func getAcceptConn(id uint64) net.Conn {
	acceptMutex.Lock()
	defer acceptMutex.Unlock()
	if conn, ok := acceptMap[id]; ok {
		delete(acceptMap, id)
		return conn
	}
	return nil
}

func forwardConnection(stream net.Conn, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		_, _ = io.Copy(conn, stream)
		if cw, ok := conn.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			// close the entire stream since there is no half-close
			time.Sleep(200 * time.Millisecond)
			_ = conn.Close()
		}
		wg.Done()
	}()
	go func() {
		_, _ = io.Copy(stream, conn)
		if cw, ok := stream.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			// close the entire stream since there is no half-close
			time.Sleep(200 * time.Millisecond)
			_ = stream.Close()
		}
		wg.Done()
	}()
	wg.Wait()
}
