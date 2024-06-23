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
	"os"
	"os/exec"

	"github.com/trzsz/go-arg"
)

const kTsshdVersion = "0.1.0"

type tsshdArgs struct {
}

func (tsshdArgs) Description() string {
	return "tsshd works with `tssh --udp`, just like mosh-server.\n"
}

func (tsshdArgs) Version() string {
	return fmt.Sprintf("trzsz sshd %s", kTsshdVersion)
}

func background() (bool, io.ReadCloser, error) {
	if v := os.Getenv("TRZSZ-SSHD-BACKGROUND"); v == "TRUE" {
		return false, nil, nil
	}
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "TRZSZ-SSHD-BACKGROUND=TRUE")
	cmd.SysProcAttr = getSysProcAttr()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return true, nil, err
	}
	if err := cmd.Start(); err != nil {
		return true, nil, err
	}
	return true, stdout, nil
}

// TsshdMain is the main function of `tsshd` binary.
func TsshdMain() int {
	var args tsshdArgs
	arg.MustParse(&args)

	parent, stdout, err := background()
	if err != nil {
		fmt.Fprintf(os.Stderr, "run in background failed: %v\n", err)
		return 1
	}

	if parent {
		defer stdout.Close()
		if _, err := io.Copy(os.Stdout, stdout); err != nil {
			fmt.Fprintf(os.Stderr, "copy stdout failed: %v\n", err)
			return 2
		}
		return 0
	}

	listener, err := initServer(&args)
	if err != nil {
		fmt.Println(err)
		os.Stdout.Close()
		return 3
	}

	os.Stdout.Close()

	serve(listener)

	return 0
}
