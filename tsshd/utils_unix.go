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
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/google/shlex"
	"golang.org/x/sys/unix"
)

type tsshdPty struct {
	cmd    *exec.Cmd
	ptmx   *os.File
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func (p *tsshdPty) Wait() error {
	return p.cmd.Wait()
}

func (p *tsshdPty) Close() error {
	return p.ptmx.Close()
}

func (p *tsshdPty) GetExitCode() int {
	return p.cmd.ProcessState.ExitCode()
}

func (p *tsshdPty) Resize(cols, rows int) error {
	return pty.Setsize(p.ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

// Testing showed that sending SIGWINCH without an actual size change
// does not reliably trigger a redraw in shells such as bash. When the
// terminal size changes, the resize operation itself already generates
// the necessary SIGWINCH signal, so an explicit signal is unnecessary.
func (p *tsshdPty) Redraw() error {
	pgid, err := unix.IoctlGetInt(int(p.ptmx.Fd()), unix.TIOCGPGRP)
	if err != nil {
		return fmt.Errorf("get foreground process group failed: %v", err)
	}
	if pgid <= 0 {
		return fmt.Errorf("invalid foreground process group: %d", pgid)
	}
	// TIOCGPGRP returns the foreground process group of the PTY.
	// Use a negative pid to send SIGWINCH to the entire process group.
	if err = unix.Kill(-pgid, unix.SIGWINCH); err != nil {
		return fmt.Errorf("send SIGWINCH to process group [%d] failed: %v", pgid, err)
	}
	return nil
}

func (p *tsshdPty) getPgid() (int, error) {
	pgid, err := unix.IoctlGetInt(int(p.ptmx.Fd()), unix.TIOCGPGRP)
	if err != nil {
		return 0, fmt.Errorf("get foreground process group failed: %v", err)
	}
	if pgid <= 0 {
		return 0, fmt.Errorf("invalid pgid (no foreground process): %d", pgid)
	}
	return pgid, nil
}

func newTsshdPty(cmd *exec.Cmd, cols, rows int) (*tsshdPty, error) {
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return nil, err
	}
	return &tsshdPty{cmd, ptmx, ptmx, ptmx}, nil
}

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}

func splitCommandLine(command string) ([]string, error) {
	return shlex.Split(command)
}

func listenForAgent(id uint64) (net.Listener, string, error) {
	sockDir, err := getSocketDir()
	if err != nil {
		tempDir, err := os.MkdirTemp("", "tsshd-") // the directory is created with mode 0o700 (before umask)
		if err != nil {
			return nil, "", fmt.Errorf("mkdir temp failed: %v", err)
		}
		addOnExitFunc(func() { _ = os.RemoveAll(tempDir) })
		sockDir = tempDir
	}

	agentPath := filepath.Join(sockDir, fmt.Sprintf("agent-%d-%d", os.Getpid(), id))

	listener, err := listenOnSocket(agentPath)
	if err != nil {
		return nil, "", err
	}

	return listener, agentPath, nil
}

func listenForSocketServer() (net.Listener, error) {
	sockDir, err := getSocketDir()
	if err != nil {
		return nil, err
	}

	sockPath := filepath.Join(sockDir, fmt.Sprintf("socket-%d", os.Getpid()))
	return listenOnSocket(sockPath)
}

func listenOnSocket(sockPath string) (net.Listener, error) {
	if info, err := os.Lstat(sockPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("socket [%s] exists and is not socket", sockPath)
		}
		if err := os.Remove(sockPath); err != nil {
			return nil, fmt.Errorf("remove stale socket [%s] failed: %v", sockPath, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat socket [%s] failed: %v", sockPath, err)
	}

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("listen on [%s] failed: %v", sockPath, err)
	}

	if err := os.Chmod(sockPath, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(sockPath)
		return nil, fmt.Errorf("chmod socket [%s] failed: %v", sockPath, err)
	}

	_ = newFileUnlinker(sockPath, listener)

	debug("listen on socket [%s] success", sockPath)

	return listener, nil
}

func getSocketDir() (string, error) {
	sockDir := func() string {
		if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
			if isDirExist(dir) {
				return filepath.Join(dir, "tsshd")
			}
			debug("XDG_RUNTIME_DIR [%s] is not directory", dir)
		}

		if home := os.Getenv("HOME"); home != "" {
			dir := filepath.Join(home, ".local", "run")
			if isDirExist(dir) {
				return filepath.Join(dir, "tsshd")
			}
			if err := os.MkdirAll(dir, 0700); err != nil {
				debug("create runtime dir [%s] failed: %v", dir, err)
			} else {
				return filepath.Join(dir, "tsshd")
			}
		}

		return filepath.Join(os.TempDir(), fmt.Sprintf("tsshd-%d", os.Getuid()))
	}()

	info, err := os.Lstat(sockDir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(sockDir, 0700); err != nil {
			return "", fmt.Errorf("create socket dir [%s] failed: %v", sockDir, err)
		}
		info, err = os.Lstat(sockDir)
	}
	if err != nil {
		return "", fmt.Errorf("stat socket dir [%s] failed: %v", sockDir, err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("socket dir [%s] is symlink", sockDir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("socket dir [%s] is not directory", sockDir)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("socket dir [%s] type invalid", sockDir)
	}
	if int64(stat.Uid) != int64(os.Getuid()) {
		return "", fmt.Errorf("socket dir [%s] owner mismatch: uid=%d owner=%d", sockDir, os.Getuid(), stat.Uid)
	}

	if info.Mode().Perm()&0077 != 0 {
		if err := os.Chmod(sockDir, 0700); err != nil {
			return "", fmt.Errorf("chmod socket dir [%s] failed: %w", sockDir, err)
		}
	}

	return sockDir, nil
}

func listSocketPaths() ([]*socketPath, error) {
	sockDir, err := getSocketDir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(sockDir)
	if err != nil {
		return nil, fmt.Errorf("read dir [%s] failed: %v", sockDir, err)
	}

	var socketPaths []*socketPath
	for _, entry := range entries {
		name := entry.Name()

		if !strings.HasPrefix(name, "socket-") {
			continue
		}

		pid, err := strconv.Atoi(strings.TrimPrefix(name, "socket-"))
		if err != nil {
			continue
		}
		if syscall.Kill(pid, 0) != nil {
			continue
		}

		path := filepath.Join(sockDir, name)

		info, err := os.Lstat(path)
		if err != nil {
			continue
		}

		if info.Mode()&os.ModeSocket == 0 {
			continue
		}

		socketPaths = append(socketPaths, &socketPath{pid, path})
	}

	return socketPaths, nil
}

func getSocketPath(pid int) (string, error) {
	if syscall.Kill(pid, 0) != nil {
		return "", fmt.Errorf("tsshd process [%d] does not exist", pid)
	}

	sockDir, err := getSocketDir()
	if err != nil {
		return "", err
	}

	sockPath := filepath.Join(sockDir, fmt.Sprintf("socket-%d", pid))

	info, err := os.Lstat(sockPath)
	if err != nil {
		return "", fmt.Errorf("stat socket [%s] failed: %v", sockPath, err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		return "", fmt.Errorf("path [%s] is not a socket", sockPath)
	}

	return sockPath, nil
}

func connectSocket(path string) (net.Conn, error) {
	return net.DialTimeout("unix", path, 1*time.Second)
}

func getProcInfos() (map[int]*procInfo, error) {
	cmd := exec.Command("ps", "-eo", "stat,pid,ppid,pgid,comm")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ps command failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) <= 1 {
		return nil, fmt.Errorf("no process found")
	}

	procs := make(map[int]*procInfo)

	for i := 1; i < len(lines); i++ { // skip the header line.
		fields := strings.Fields(lines[i])
		if len(fields) < 5 {
			continue
		}

		if stat := fields[0]; strings.HasPrefix(stat, "Z") {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		ppid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		pgid, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}
		// join the remaining fields for robustness.
		name := strings.Join(fields[4:], " ")

		procs[pid] = &procInfo{
			pid:  pid,
			ppid: ppid,
			pgid: pgid,
			name: name,
		}
	}

	return procs, nil
}

func getForegroundProcess(pgid int) (string, error) {
	procs, err := getProcInfos()
	if err != nil {
		return "", err
	}

	procs = findAllDescendants(procs, os.Getpid())

	groupPgid := pgid
	if groupPgid == 0 {
		for _, p := range procs {
			if p.pgid > groupPgid {
				groupPgid = p.pgid
			}
		}
	}

	for _, p := range procs {
		if p.pgid != groupPgid {
			delete(procs, p.pid)
		}
	}

	leaves := findLeafProcesses(procs)

	var best *procInfo
	for _, p := range leaves {
		if best == nil {
			best = p
			continue
		}
		if p.pid < best.pid {
			best = p
		}
	}

	if best != nil {
		return best.name, nil
	}

	return "", fmt.Errorf("no leaf process")
}
