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
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var kDefaultConnectTimeout = 10 * time.Second

var exitChan = make(chan int, 1)

type tsshdArgs struct {
	Help           bool
	VerShort       bool
	VerDetailed    bool
	KCP            bool
	TCP            bool
	IPv4           bool
	IPv6           bool
	Debug          bool
	MTU            uint16
	Port           string
	ConnectTimeout time.Duration
}

func printHelp() int {
	fmt.Printf("usage: tsshd [-h|-v|-V] [--kcp] [--tcp] [--ipv4] [--ipv6] [--debug] [--mtu N] [--port low-high] [--connect-timeout t]\n\n" +
		"tsshd: trzsz-ssh(tssh) server that supports connection migration for roaming.\n\n" +
		"optional arguments:\n" +
		"  -h, --help             show this help message and exit\n" +
		"  -v                     show short version number and exit\n" +
		"  -V                     show detailed version info and exit\n" +
		"  --kcp                  KCP protocol (default is QUIC protocol)\n" +
		"  --tcp                  Use UDP-over-TCP to bypass UDP blocking\n" +
		"  --ipv4                 UDP only listens on IPv4, ignoring IPv6\n" +
		"  --ipv6                 UDP only listens on IPv6, ignoring IPv4\n" +
		"  --debug                Send debugging messages to the client\n" +
		"  --mtu N                Sets the Maximum Transmission Unit (MTU)\n" +
		"  --port low-high        UDP port range that the tsshd listens on\n" +
		"  --connect-timeout t    The timeout for tssh connecting to tsshd\n")
	return 0
}

func parseTsshdArgs() *tsshdArgs {
	args := &tsshdArgs{}
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-h", "--help":
			args.Help = true
		case "-v", "--version":
			args.VerShort = true
		case "-V":
			args.VerDetailed = true
		case "--kcp":
			args.KCP = true
		case "--tcp":
			args.TCP = true
		case "--ipv4":
			args.IPv4 = true
		case "--ipv6":
			args.IPv6 = true
		case "--debug":
			args.Debug = true
		case "--mtu":
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				if mtu, err := strconv.ParseUint(os.Args[i+1], 10, 16); err == nil {
					args.MTU = uint16(mtu)
				}
				i++
			}
		case "--port":
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				args.Port = os.Args[i+1]
				i++
			}
		case "--connect-timeout":
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				if timeout, err := strconv.ParseUint(os.Args[i+1], 10, 32); err == nil {
					args.ConnectTimeout = time.Duration(timeout) * time.Second
				}
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
		return printHelp()
	}
	if args.VerShort {
		return printVersionShort()
	}
	if args.VerDetailed {
		return printVersionDetailed()
	}

	parent, stdout, err := background()
	if err != nil {
		fmt.Fprintf(os.Stderr, "run in background failed: %v\n", err)
		return 1
	}

	if parent {
		defer func() { _ = stdout.Close() }()
		if _, err := io.Copy(os.Stdout, stdout); err != nil {
			fmt.Fprintf(os.Stderr, "copy stdout failed: %v\n", err)
			return 2
		}
		return 0
	}

	// cleanup on exit
	defer cleanupOnExit()

	// default connect timeout
	if args.ConnectTimeout <= 0 {
		args.ConnectTimeout = kDefaultConnectTimeout
	}

	// handle exit signals
	handleExitSignals()

	// init sshd_config
	initSshdConfig()

	// init log level
	enableWarningLogging = true
	if args.Debug {
		enableDebugLogging = true
		debug("tsshd version: %s", getTsshdVersion())
	} else {
		if v := strings.ToLower(getSshdConfig("LogLevel")); v == "quiet" || v == "fatal" {
			enableWarningLogging = false
		}
	}

	// init tsshd server
	kcpListener, quicListener, err := initServer(args)
	if err != nil {
		fmt.Println(err)
		_ = os.Stdout.Close()
		return 3
	}

	_ = os.Stdout.Close()

	if kcpListener != nil {
		defer func() { _ = kcpListener.Close() }()
		go serveKCP(kcpListener, args.MTU)
	}
	if quicListener != nil {
		defer func() { _ = quicListener.Close() }()
		go serveQUIC(quicListener)
	}

	go func() {
		// should be connected in time
		time.Sleep(args.ConnectTimeout)
		if !serving.Load() {
			exitChan <- 1
		}
	}()

	return <-exitChan
}
