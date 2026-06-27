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
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/UserExistsError/conpty"
	"golang.org/x/sys/windows"
)

type safeConPty struct {
	*conpty.ConPty
	closed atomic.Bool
	mutex  sync.Mutex
}

func (p *safeConPty) Close() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if !p.closed.CompareAndSwap(false, true) {
		// crash if close multiple times
		return nil
	}
	return p.ConPty.Close()
}

func (p *safeConPty) Resize(width, height int) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.closed.Load() {
		// crash if resize after close
		return nil
	}
	return p.ConPty.Resize(width, height)
}

func (p *tsshdPty) getPgid() (int, error) {
	return 0, nil
}

type tsshdPty struct {
	spty   *safeConPty
	stdin  io.WriteCloser
	stdout io.ReadCloser
	code   int
}

func (p *tsshdPty) Wait() error {
	code, err := p.spty.Wait(context.Background())
	p.code = int(code)
	_ = p.stdout.Close() // stdout needs to be closed so that the client knows there is no more data to read
	return err
}

func (p *tsshdPty) Close() error {
	return p.spty.Close()
}

func (p *tsshdPty) GetExitCode() int {
	return p.code
}

func (p *tsshdPty) Resize(cols, rows int) error {
	if cols < 1 || rows < 1 {
		return fmt.Errorf("terminal size (%d, %d) is too small", cols, rows)
	}
	return p.spty.Resize(cols, rows)
}

func (p *tsshdPty) Redraw() error {
	return fmt.Errorf("signal-based redraw is not supported on Windows")
}

func newTsshdPty(cmd *exec.Cmd, cols, rows int) (*tsshdPty, error) {
	var cmdLine strings.Builder
	for _, arg := range cmd.Args {
		if cmdLine.Len() > 0 {
			cmdLine.WriteString(" ")
		}
		cmdLine.WriteString(windows.EscapeArg(arg))
	}
	cpty, err := conpty.Start(cmdLine.String(), conpty.ConPtyDimensions(cols, rows), conpty.ConPtyEnv(cmd.Env))
	if err != nil {
		return nil, err
	}
	spty := &safeConPty{ConPty: cpty}
	return &tsshdPty{spty, spty, spty, -1}, nil
}

func getUserShell() (string, error) {
	return "PowerShell", nil
}

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_BREAKAWAY_FROM_JOB | windows.DETACHED_PROCESS,
	}
}

func splitCommandLine(command string) ([]string, error) {
	return windows.DecomposeCommandLine(command)
}

func listenForAgent(id uint64) (net.Listener, string, error) {
	return listenOnPipe(fmt.Sprintf("agent-%d-%d", os.Getpid(), id))
}

func listenForSocketServer() (net.Listener, error) {
	listener, _, err := listenOnPipe(fmt.Sprintf("socket-%d", os.Getpid()))
	return listener, err
}

func listenOnPipe(name string) (net.Listener, string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, "", fmt.Errorf("get current user failed: %v", err)
	}

	pipeConfig := &winio.PipeConfig{
		SecurityDescriptor: fmt.Sprintf("D:P(A;;GA;;;%s)", currentUser.Uid),
	}

	pipePath := fmt.Sprintf(`\\.\pipe\tsshd\%s\%s`, currentUser.Uid, name)

	listener, err := winio.ListenPipe(pipePath, pipeConfig)
	if err != nil {
		return nil, "", fmt.Errorf("listen on [%s] failed: %v", pipePath, err)
	}

	addOnExitFunc(func() { _ = listener.Close() })

	return listener, pipePath, nil
}

func listSocketPaths() ([]*socketPath, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("get current user failed: %v", err)
	}
	prefix := fmt.Sprintf(`tsshd\%s\socket-`, currentUser.Uid)

	pattern := `\\.\pipe\*`
	ptr, err := windows.UTF16PtrFromString(pattern)
	if err != nil {
		return nil, fmt.Errorf("ptr from string [%s] failed: %v", pattern, err)
	}

	var data windows.Win32finddata
	handle, err := windows.FindFirstFile(ptr, &data)
	if err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return nil, nil
		}
		return nil, fmt.Errorf("find first file [%s] failed: %v", pattern, err)
	}
	defer windows.FindClose(handle)

	var socketPaths []*socketPath
	for {
		name := windows.UTF16ToString(data.FileName[:])
		if strings.HasPrefix(name, prefix) {
			if pid, err := strconv.Atoi(name[len(prefix):]); err == nil {
				socketPaths = append(socketPaths, &socketPath{pid, `\\.\pipe\` + name})
			}
		}
		err = windows.FindNextFile(handle, &data)
		if err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				break
			}
			return nil, err
		}
	}

	return socketPaths, nil
}

func getSocketPath(pid int) (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get current user failed: %v", err)
	}

	pipePath := fmt.Sprintf(`\\.\pipe\tsshd\%s\socket-%d`, currentUser.Uid, pid)
	return pipePath, nil
}

func connectSocket(path string) (net.Conn, error) {
	timeout := 1 * time.Second
	return winio.DialPipe(path, &timeout)
}

func getProcInfos() (map[int]*procInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = windows.Process32First(snapshot, &pe32)
	if err != nil {
		return nil, fmt.Errorf("Process32First failed: %v", err)
	}

	procs := make(map[int]*procInfo)

	for err == nil {
		pid := int(pe32.ProcessID)
		ppid := int(pe32.ParentProcessID)
		name := windows.UTF16ToString(pe32.ExeFile[:])

		procs[pid] = &procInfo{
			pid:  pid,
			ppid: ppid,
			name: name,
		}

		err = windows.Process32Next(snapshot, &pe32)
	}

	if err != windows.ERROR_NO_MORE_FILES {
		return nil, fmt.Errorf("Process32Next failed: %v", err)
	}

	return procs, nil
}

func getForegroundProcess(_ int) (string, error) {
	procs, err := getProcInfos()
	if err != nil {
		return "", err
	}

	procs = findAllDescendants(procs, os.Getpid())

	leaves := findLeafProcesses(procs)

	var best *procInfo

out:
	for _, p := range leaves {
		for p.name == "conhost.exe" {
			if parent, ok := procs[p.ppid]; ok {
				p = parent
			} else {
				continue out
			}
		}

		if best == nil {
			best = p
			continue
		}

		if p.pid > best.pid {
			best = p
		}
	}

	if best != nil {
		return best.name, nil
	}

	return "", fmt.Errorf("no leaf process")
}
