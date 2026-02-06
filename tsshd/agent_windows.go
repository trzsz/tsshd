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
	"os/user"

	"github.com/Microsoft/go-winio"
)

func listenForAgent() (net.Listener, string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, "", fmt.Errorf("get current user failed: %v", err)
	}

	pipeConfig := &winio.PipeConfig{
		SecurityDescriptor: fmt.Sprintf("D:P(A;;GA;;;%s)", currentUser.Uid),
	}
	pipePath := fmt.Sprintf(`\\.\pipe\tsshd-agent-%d`, os.Getpid())
	listener, err := winio.ListenPipe(pipePath, pipeConfig)
	if err != nil {
		return nil, "", fmt.Errorf("listen on [%s] failed: %v", pipePath, err)
	}

	addOnExitFunc(func() {
		_ = listener.Close()
	})

	return listener, pipePath, nil
}
