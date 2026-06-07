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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const kSocketTimeout = 3 * time.Second

var globalSocketInfo *socketInfo

type socketInfo struct {
	startTime   int64
	sessionName string
	serverInfo  *ServerInfo
	attachMutex sync.Mutex
}

type socketPath struct {
	pid  int
	path string
}

func startSocketServer(serverInfo *ServerInfo) {
	globalSocketInfo = &socketInfo{
		startTime:  time.Now().Unix(),
		serverInfo: serverInfo,
	}

	listener, err := listenForSocketServer()
	if err != nil {
		warning("socket server listen failed: %v", err)
		return
	}
	defer func() { _ = listener.Close() }()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if isClosedError(err) {
				return
			}
			warning("socket server accept failed: %v", err)
			return
		}

		if err := conn.SetDeadline(time.Now().Add(kSocketTimeout)); err != nil {
			warning("socket set deadline failed: %v", err)
			continue
		}

		go handleSocketConn(conn)
	}
}

func handleSocketConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	cmd, err := recvCommand(conn)
	if err != nil {
		debug("socket read command failed: %v", err)
		return
	}

	switch cmd {
	case "info":
		err = handleInfoRequest(conn)
	case "view":
		err = handleViewRequest(conn)
	case "attach":
		err = handleAttachRequest(conn)
	default:
		debug("socket unknown command: %s", cmd)
	}

	if err != nil && enableDebugLogging {
		debug("handle request [%s] failed: %v", cmd, err)
	}
}

func handleInfoRequest(conn net.Conn) error {
	info := BaseInfo{
		Time: globalSocketInfo.startTime,
		Name: globalSocketInfo.sessionName,
	}

	for _, sess := range getAllSessions() {
		var title string
		if sess.screenObj != nil {
			sess.screenMu.Lock()
			title = sess.screenObj.Title
			sess.screenMu.Unlock()
		}
		info.Sessions = append(info.Sessions, SessionInfo{ID: sess.id, Title: title})
	}

	infoStr, err := json.Marshal(info)
	if err != nil {
		_, _ = fmt.Fprintf(conn, "ERROR: generate base info failed: %v\n", err)
		return fmt.Errorf("json marshal base info failed: %v", err)
	}

	if _, err := conn.Write(infoStr); err != nil {
		return fmt.Errorf("write info response failed: %v", err)
	}

	return nil
}

func handleViewRequest(conn net.Conn) error {
	var msg viewMessage
	if err := recvMessage(conn, &msg); err != nil {
		return fmt.Errorf("recv view request failed: %v", err)
	}

	sess := getSessionByID(msg.ID)

	if sess == nil {
		_, err := fmt.Fprintf(conn, "ERROR: session [%d] not found\r\n", msg.ID)
		if err != nil {
			return fmt.Errorf("write view response failed: %v", err)
		}
		return nil
	}

	if sess.screenObj == nil {
		_, err := fmt.Fprintf(conn, "ERROR: session [%d] was not started with attachable support\r\n", msg.ID)
		if err != nil {
			return fmt.Errorf("write view response failed: %v", err)
		}
		return nil
	}

	sess.screenMu.Lock()
	contents := sess.screenObj.Display()
	sess.screenMu.Unlock()

	for _, line := range contents {
		if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil {
			return fmt.Errorf("write view response failed: %v", err)
		}
	}

	return nil
}

func handleAttachRequest(conn net.Conn) error {
	globalSocketInfo.attachMutex.Lock()
	defer globalSocketInfo.attachMutex.Unlock()

	globalSocketInfo.serverInfo.ClientID++
	if globalSocketInfo.serverInfo.ClientID == 0 {
		// Skip the reserved zero ClientID after uint64 wraparound.
		globalSocketInfo.serverInfo.ClientID++
	}

	infoStr, err := json.Marshal(globalSocketInfo.serverInfo)
	if err != nil {
		_, _ = fmt.Fprintf(conn, "ERROR: generate server info failed: %v\n", err)
		return fmt.Errorf("json marshal server info failed: %v", err)
	}

	debug("allocated attach client id [%x]", globalSocketInfo.serverInfo.ClientID)

	if _, err := fmt.Fprintf(conn, "\a%s\n", infoStr); err != nil {
		return fmt.Errorf("write attach response failed: %v", err)
	}

	return nil
}

func handleListCommand() (int, error) {
	socketPaths, err := listSocketPaths()
	if err != nil {
		return kExitCodeListFailed, err
	}

	items := make([]*ServerItem, len(socketPaths))

	var wg sync.WaitGroup
	for i := range socketPaths {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			info, err := queryBaseInfo(socketPaths[i].path)
			if err != nil {
				info = err.Error()
			}

			items[i] = &ServerItem{
				Pid:  socketPaths[i].pid,
				Info: info,
			}
		}(i)
	}
	wg.Wait()

	buf, err := json.Marshal(items)
	if err != nil {
		return kExitCodeListFailed, fmt.Errorf("server items marshal failed: %w", err)
	}

	fmt.Printf("%s\r\n", string(buf))
	return 0, nil
}

func queryBaseInfo(path string) (string, error) {
	conn, err := connectSocket(path)
	if err != nil {
		return "", fmt.Errorf("connect socket [%s] failed: %v", path, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(kSocketTimeout)); err != nil {
		return "", fmt.Errorf("set attach deadline failed: %v", err)
	}

	if err := sendCommand(conn, "info"); err != nil {
		return "", fmt.Errorf("send info request failed: %v", err)
	}

	buf, err := io.ReadAll(conn)
	if err != nil {
		return "", fmt.Errorf("read info response failed: %v", err)
	}

	return string(buf), nil
}

func handleViewCommand(pidAndSid string) (int, error) {
	tokens := strings.Split(pidAndSid, ".")
	if len(tokens) != 2 {
		return kExitCodeViewFailed, fmt.Errorf("invalid view target [%s], expected <pid>.<sid>", pidAndSid)
	}
	pid, err := strconv.Atoi(tokens[0])
	if err != nil {
		return kExitCodeViewFailed, fmt.Errorf("invalid process id in view target [%s]: %v", pidAndSid, err)
	}
	sid, err := strconv.ParseUint(tokens[1], 10, 64)
	if err != nil {
		return kExitCodeViewFailed, fmt.Errorf("invalid session id in view target [%s]: %v", pidAndSid, err)
	}

	path, err := getSocketPath(pid)
	if err != nil {
		return kExitCodeViewFailed, err
	}

	conn, err := connectSocket(path)
	if err != nil {
		return kExitCodeViewFailed, fmt.Errorf("connect socket [%s] failed: %v", path, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(kSocketTimeout)); err != nil {
		return kExitCodeViewFailed, fmt.Errorf("set view deadline failed: %v", err)
	}

	if err := sendCommandAndMessage(conn, "view", &viewMessage{sid}); err != nil {
		return kExitCodeViewFailed, fmt.Errorf("send view request failed: %v", err)
	}

	if _, err := io.Copy(os.Stdout, conn); err != nil {
		return kExitCodeViewFailed, fmt.Errorf("copy view response failed: %v", err)
	}

	return 0, nil
}

func handleAttachCommand(pidStr string) (int, error) {
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return kExitCodeAttachFailed, fmt.Errorf("invalid attach target [%s], expected <pid>:: %v", pidStr, err)
	}

	path, err := getSocketPath(pid)
	if err != nil {
		return kExitCodeAttachFailed, err
	}

	conn, err := connectSocket(path)
	if err != nil {
		return kExitCodeAttachFailed, fmt.Errorf("connect socket [%s] failed: %v", path, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(kSocketTimeout)); err != nil {
		return kExitCodeAttachFailed, fmt.Errorf("set attach deadline failed: %v", err)
	}

	if err := sendCommand(conn, "attach"); err != nil {
		return kExitCodeAttachFailed, fmt.Errorf("send attach request failed: %v", err)
	}

	if _, err := io.Copy(os.Stdout, conn); err != nil {
		return kExitCodeAttachFailed, fmt.Errorf("copy attach response failed: %v", err)
	}

	return 0, nil
}
