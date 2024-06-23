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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

const kNoErrorMsg = "_TSSHD_NO_ERROR_"

type ServerInfo struct {
	Ver  string
	Pass string
	Salt string
	Port int
}

type ErrorMessage struct {
	Msg string
}

type BusMessage struct {
	Timeout time.Duration
}

type StartMessage struct {
	ID    uint64
	Pty   bool
	Shell bool
	Name  string
	Args  []string
	Cols  int
	Rows  int
	Envs  map[string]string
}

type ExitMessage struct {
	ID       uint64
	ExitCode int
}

type ResizeMessage struct {
	ID   uint64
	Cols int
	Rows int
}

type StderrMessage struct {
	ID uint64
}

type DialMessage struct {
	Network string
	Addr    string
	Timeout time.Duration
}

type ListenMessage struct {
	Network string
	Addr    string
}

type AcceptMessage struct {
	ID uint64
}

func writeAll(dst io.Writer, data []byte) error {
	m := 0
	l := len(data)
	for m < l {
		n, err := dst.Write(data[m:])
		if err != nil {
			return err
		}
		m += n
	}
	return nil
}

func SendCommand(session *kcp.UDPSession, command string) error {
	if len(command) == 0 {
		return fmt.Errorf("send command is empty")
	}
	if len(command) > 255 {
		return fmt.Errorf("send command too long: %s", command)
	}
	buffer := make([]byte, len(command)+1)
	buffer[0] = uint8(len(command))
	copy(buffer[1:], []byte(command))
	if err := writeAll(session, buffer); err != nil {
		return fmt.Errorf("send command write buffer failed: %v", err)
	}
	return nil
}

func RecvCommand(session *kcp.UDPSession) (string, error) {
	length := make([]byte, 1)
	if _, err := session.Read(length); err != nil {
		return "", fmt.Errorf("recv command read length failed: %v", err)
	}
	command := make([]byte, length[0])
	if _, err := io.ReadFull(session, command); err != nil {
		return "", fmt.Errorf("recv command read buffer failed: %v", err)
	}
	return string(command), nil
}

func SendMessage(session *kcp.UDPSession, msg any) error {
	msgBuf, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("send message marshal failed: %v", err)
	}
	buffer := make([]byte, len(msgBuf)+4)
	binary.BigEndian.PutUint32(buffer, uint32(len(msgBuf)))
	copy(buffer[4:], msgBuf)
	if err := writeAll(session, buffer); err != nil {
		return fmt.Errorf("send message write buffer failed: %v", err)
	}
	return nil
}

func RecvMessage(session *kcp.UDPSession, msg any) error {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(session, lenBuf); err != nil {
		return fmt.Errorf("recv message read length failed: %v", err)
	}
	msgBuf := make([]byte, binary.BigEndian.Uint32(lenBuf))
	if _, err := io.ReadFull(session, msgBuf); err != nil {
		return fmt.Errorf("recv message read buffer failed: %v", err)
	}
	if err := json.Unmarshal(msgBuf, msg); err != nil {
		return fmt.Errorf("recv message unmarshal failed: %v", err)
	}
	return nil
}

func SendError(session *kcp.UDPSession, err error) {
	if e := SendMessage(session, ErrorMessage{err.Error()}); e != nil {
		trySendErrorMessage("send error [%v] failed: %v", err, e)
	}
}

func SendSuccess(session *kcp.UDPSession) error {
	return SendMessage(session, ErrorMessage{kNoErrorMsg})
}

func RecvError(session *kcp.UDPSession) error {
	var errMsg ErrorMessage
	if err := RecvMessage(session, &errMsg); err != nil {
		return fmt.Errorf("recv error failed: %v", err)
	}
	if errMsg.Msg != kNoErrorMsg {
		return fmt.Errorf(errMsg.Msg)
	}
	return nil
}

func NewKcpSession(addr string, key []byte, cmd string) (session *kcp.UDPSession, err error) {
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, fmt.Errorf("new aes block crypt failed: %v", err)
	}

	done := make(chan struct{}, 1)
	go func() {
		defer func() {
			if err != nil && session != nil {
				session.Close()
			}
			done <- struct{}{}
			close(done)
		}()
		session, err = kcp.DialWithOptions(addr, block, 10, 3)
		if err != nil {
			err = fmt.Errorf("kcp dial [%s] [%s] failed: %v", addr, cmd, err)
			return
		}
		session.SetNoDelay(1, 10, 2, 1)
		if err = SendCommand(session, cmd); err != nil {
			err = fmt.Errorf("kcp send command [%s] [%s] failed: %v", addr, cmd, err)
			return
		}
		if err = RecvError(session); err != nil {
			err = fmt.Errorf("kcp new session [%s] [%s] failed: %v", addr, cmd, err)
			return
		}
	}()

	select {
	case <-time.After(10 * time.Second):
		err = fmt.Errorf("kcp new session [%s] [%s] timeout", addr, cmd)
	case <-done:
	}
	return
}
