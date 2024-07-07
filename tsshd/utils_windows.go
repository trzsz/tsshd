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
	"context"
	"io"
	"os/exec"
	"strings"
	"syscall"

	"github.com/trzsz/tsshd/internal/conpty"
	"golang.org/x/sys/windows"
)

type tsshdPty struct {
	cpty   *conpty.ConPty
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func (p *tsshdPty) Wait() error {
	_, err := p.cpty.Wait(context.Background())
	_ = p.stdout.Close()
	return err
}

func (p *tsshdPty) Close() error {
	return p.cpty.Close()
}

func (p *tsshdPty) Resize(cols, rows int) error {
	return p.cpty.Resize(cols, rows)
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
	return &tsshdPty{cpty, cpty, cpty}, nil
}

func getUserShell() (string, error) {
	return "PowerShell", nil
}

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_BREAKAWAY_FROM_JOB | windows.DETACHED_PROCESS,
	}
}
