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
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const kTsshdVersion = "0.1.4"

var exitChan = make(chan int, 1)

type tsshdArgs struct {
	Help    bool
	Version bool
	KCP     bool
	Proxy   bool
	Port    string
}

func printVersion() {
	fmt.Printf("trzsz sshd %s\n", kTsshdVersion)
}

func printHelp() {
	fmt.Printf("usage: tsshd [-h] [-v] [--kcp] [--proxy] [--port low-high]\n\n" +
		"tsshd works with `tssh --udp`, just like mosh-server.\n\n" +
		"optional arguments:\n" +
		"  -h, --help             show this help message and exit\n" +
		"  -v, --version          show program's version number and exit\n" +
		"  --kcp                  KCP protocol (default is QUIC protocol)\n" +
		"  --proxy                With UDP proxy for connection migration\n" +
		"  --port low-high        UDP port range that the tsshd listens on\n")
}

func parseTsshdArgs() *tsshdArgs {
	args := &tsshdArgs{}
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-h", "--help":
			args.Help = true
			return args
		case "-v", "--version":
			args.Version = true
			return args
		case "--kcp":
			args.KCP = true
		case "--proxy":
			args.Proxy = true
		case "--port":
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				args.Port = os.Args[i+1]
				i++
			}
		}
	}
	return args
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

var onExitFuncs []func()

func cleanupOnExit() {
	for i := len(onExitFuncs) - 1; i >= 0; i-- {
		onExitFuncs[i]()
	}
}

// TsshdMain is the main function of `tsshd` binary.
func TsshdMain() int {
	args := parseTsshdArgs()
	if args.Help {
		printHelp()
		return 0
	}
	if args.Version {
		printVersion()
		return 0
	}

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

	// cleanup on exit
	defer cleanupOnExit()

	// handle exit signals
	handleExitSignals()

	kcpListener, quicListener, err := initServer(args)
	if err != nil {
		fmt.Println(err)
		os.Stdout.Close()
		return 3
	}

	os.Stdout.Close()

	if kcpListener != nil {
		defer kcpListener.Close()
		go serveKCP(kcpListener)
	}
	if quicListener != nil {
		defer quicListener.Close()
		go serveQUIC(quicListener)
	}

	go func() {
		// should be connected within 20 seconds
		time.Sleep(20 * time.Second)
		if !serving.Load() {
			exitChan <- 1
		}
	}()

	return <-exitChan
}

func handleExitSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGTERM, // Default signal for the kill command
		syscall.SIGINT,  // Ctrl+C signal
		syscall.SIGHUP,  // Terminal closed (System reboot/shutdown)
	)

	go func() {
		<-sigChan
		trySendErrorMessage("tsshd has been terminated")
		closeAllSessions()
	}()
}
