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
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

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
	return p.spty.Resize(cols-1, rows)
}

func newTsshdPty(cmd *exec.Cmd, cols, rows int) (*tsshdPty, error) {
	var cmdLine strings.Builder
	for _, arg := range cmd.Args {
		if cmdLine.Len() > 0 {
			cmdLine.WriteString(" ")
		}
		cmdLine.WriteString(windows.EscapeArg(arg))
	}
	cpty, err := conpty.Start(cmdLine.String(), conpty.ConPtyDimensions(cols-1, rows), conpty.ConPtyEnv(cmd.Env))
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
