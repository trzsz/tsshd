//go:build !windows

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
	"fmt"
	"net"
	"os"
	"path/filepath"
)

func listenForAgent() (net.Listener, string, error) {
	tempDir, err := os.MkdirTemp("", "tsshd-")
	if err != nil {
		return nil, "", fmt.Errorf("mkdir temp failed: %v", err)
	}
	onExitFuncs = append(onExitFuncs, func() {
		_ = os.RemoveAll(tempDir)
	})

	agentPath := filepath.Join(tempDir, fmt.Sprintf("agent.%d", os.Getpid()))

	listener, err := net.Listen("unix", agentPath)
	if err != nil {
		return nil, "", fmt.Errorf("listen on [%s] failed: %v", agentPath, err)
	}

	if err := os.Chmod(agentPath, 0600); err != nil {
		warning("agent forwarding chmod [%s] failed: %v", agentPath, err)
	}

	onExitFuncs = append(onExitFuncs, func() {
		_ = listener.Close()
		_ = os.Remove(agentPath)
	})

	return listener, agentPath, nil
}
