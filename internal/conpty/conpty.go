//go:build windows
// +build windows

// Forked From: https://github.com/UserExistsError/conpty

package conpty

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32                        = windows.NewLazySystemDLL("kernel32.dll")
	fCreatePseudoConsole               = modKernel32.NewProc("CreatePseudoConsole")
	fResizePseudoConsole               = modKernel32.NewProc("ResizePseudoConsole")
	fClosePseudoConsole                = modKernel32.NewProc("ClosePseudoConsole")
	fInitializeProcThreadAttributeList = modKernel32.NewProc("InitializeProcThreadAttributeList")
	fUpdateProcThreadAttribute         = modKernel32.NewProc("UpdateProcThreadAttribute")
	ErrConPtyUnsupported               = errors.New("ConPty is not available on this version of Windows")
)

func IsConPtyAvailable() bool {
	return fCreatePseudoConsole.Find() == nil &&
		fResizePseudoConsole.Find() == nil &&
		fClosePseudoConsole.Find() == nil &&
		fInitializeProcThreadAttributeList.Find() == nil &&
		fUpdateProcThreadAttribute.Find() == nil
}

const (
	_STILL_ACTIVE                        uint32  = 259
	_S_OK                                uintptr = 0
	_PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE uintptr = 0x20016
	defaultConsoleWidth                          = 80 // in characters
	defaultConsoleHeight                         = 40 // in characters
)

type _COORD struct {
	X, Y int16
}

func (c *_COORD) Pack() uintptr {
	return uintptr((int32(c.Y) << 16) | int32(c.X))
}

type _HPCON windows.Handle

type handleIO struct {
	handle windows.Handle
}

func (h *handleIO) Read(p []byte) (int, error) {
	var numRead uint32 = 0
	err := windows.ReadFile(h.handle, p, &numRead, nil)
	return int(numRead), err
}

func (h *handleIO) Write(p []byte) (int, error) {
	var numWritten uint32 = 0
	err := windows.WriteFile(h.handle, p, &numWritten, nil)
	return int(numWritten), err
}

func (h *handleIO) Close() error {
	return windows.CloseHandle(h.handle)
}

type ConPty struct {
	hpc                          _HPCON
	pi                           *windows.ProcessInformation
	ptyIn, ptyOut, cmdIn, cmdOut *handleIO
}

func win32ClosePseudoConsole(hPc _HPCON) {
	if fClosePseudoConsole.Find() != nil {
		return
	}
	// this kills the attached process. there is no return value.
	fClosePseudoConsole.Call(uintptr(hPc))
}

func win32ResizePseudoConsole(hPc _HPCON, coord *_COORD) error {
	if fResizePseudoConsole.Find() != nil {
		return fmt.Errorf("ResizePseudoConsole not found")
	}
	ret, _, _ := fResizePseudoConsole.Call(uintptr(hPc), coord.Pack())
	if ret != _S_OK {
		return fmt.Errorf("ResizePseudoConsole failed with status 0x%x", ret)
	}
	return nil
}

func win32CreatePseudoConsole(c *_COORD, hIn, hOut windows.Handle) (_HPCON, error) {
	if fCreatePseudoConsole.Find() != nil {
		return 0, fmt.Errorf("CreatePseudoConsole not found")
	}
	var hPc _HPCON
	ret, _, _ := fCreatePseudoConsole.Call(
		c.Pack(),
		uintptr(hIn),
		uintptr(hOut),
		0,
		uintptr(unsafe.Pointer(&hPc)))
	if ret != _S_OK {
		return 0, fmt.Errorf("CreatePseudoConsole() failed with status 0x%x", ret)
	}
	return hPc, nil
}

type _StartupInfoEx struct {
	startupInfo   windows.StartupInfo
	attributeList []byte
}

func getStartupInfoExForPTY(hpc _HPCON) (*_StartupInfoEx, error) {
	if fInitializeProcThreadAttributeList.Find() != nil {
		return nil, fmt.Errorf("InitializeProcThreadAttributeList not found")
	}
	if fUpdateProcThreadAttribute.Find() != nil {
		return nil, fmt.Errorf("UpdateProcThreadAttribute not found")
	}
	var siEx _StartupInfoEx
	siEx.startupInfo.Cb = uint32(unsafe.Sizeof(windows.StartupInfo{}) + unsafe.Sizeof(&siEx.attributeList[0]))
	siEx.startupInfo.Flags |= windows.STARTF_USESTDHANDLES
	var size uintptr

	// first call is to get required size. this should return false.
	ret, _, _ := fInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	siEx.attributeList = make([]byte, size, size)
	ret, _, err := fInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(&siEx.attributeList[0])),
		1,
		0,
		uintptr(unsafe.Pointer(&size)))
	if ret != 1 {
		return nil, fmt.Errorf("InitializeProcThreadAttributeList: %v", err)
	}

	ret, _, err = fUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(&siEx.attributeList[0])),
		0,
		_PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		uintptr(hpc),
		unsafe.Sizeof(hpc),
		0,
		0)
	if ret != 1 {
		return nil, fmt.Errorf("InitializeProcThreadAttributeList: %v", err)
	}
	return &siEx, nil
}

func createConsoleProcessAttachedToPTY(hpc _HPCON, commandLine, workDir string, env []string) (*windows.ProcessInformation, error) {
	cmdLine, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		return nil, err
	}
	var currentDirectory *uint16
	if workDir != "" {
		currentDirectory, err = windows.UTF16PtrFromString(workDir)
		if err != nil {
			return nil, err
		}
	}
	var envBlock *uint16
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT)
	if env != nil {
		flags |= uint32(windows.CREATE_UNICODE_ENVIRONMENT)
		envBlock = createEnvBlock(env)
	}
	siEx, err := getStartupInfoExForPTY(hpc)
	if err != nil {
		return nil, err
	}
	var pi windows.ProcessInformation
	err = windows.CreateProcess(
		nil, // use this if no args
		cmdLine,
		nil,
		nil,
		false, // inheritHandle
		flags,
		envBlock,
		currentDirectory,
		&siEx.startupInfo,
		&pi)
	if err != nil {
		return nil, err
	}
	return &pi, nil
}

// createEnvBlock refers to syscall.createEnvBlock in go/src/syscall/exec_windows.go
// Sourced From: https://github.com/creack/pty/pull/155
func createEnvBlock(envv []string) *uint16 {
	if len(envv) == 0 {
		return &utf16.Encode([]rune("\x00\x00"))[0]
	}
	length := 0
	for _, s := range envv {
		length += len(s) + 1
	}
	length += 1

	b := make([]byte, length)
	i := 0
	for _, s := range envv {
		l := len(s)
		copy(b[i:i+l], []byte(s))
		copy(b[i+l:i+l+1], []byte{0})
		i = i + l + 1
	}
	copy(b[i:i+1], []byte{0})

	return &utf16.Encode([]rune(string(b)))[0]
}

// This will only return the first error.
func closeHandles(handles ...windows.Handle) error {
	var err error
	for _, h := range handles {
		if h != windows.InvalidHandle {
			if err == nil {
				err = windows.CloseHandle(h)
			} else {
				windows.CloseHandle(h)
			}
		}
	}
	return err
}

// Close all open handles and terminate the process.
func (cpty *ConPty) Close() error {
	// there is no return code
	win32ClosePseudoConsole(cpty.hpc)
	return closeHandles(
		cpty.pi.Process,
		cpty.pi.Thread,
		cpty.ptyIn.handle,
		cpty.ptyOut.handle,
		cpty.cmdIn.handle,
		cpty.cmdOut.handle)
}

// Wait for the process to exit and return the exit code. If context is canceled,
// Wait() will return STILL_ACTIVE and an error indicating the context was canceled.
func (cpty *ConPty) Wait(ctx context.Context) (uint32, error) {
	var exitCode uint32 = _STILL_ACTIVE
	for {
		if err := ctx.Err(); err != nil {
			return _STILL_ACTIVE, fmt.Errorf("wait canceled: %v", err)
		}
		ret, _ := windows.WaitForSingleObject(cpty.pi.Process, 1000)
		if ret != uint32(windows.WAIT_TIMEOUT) {
			err := windows.GetExitCodeProcess(cpty.pi.Process, &exitCode)
			return exitCode, err
		}
	}
}

func (cpty *ConPty) Resize(width, height int) error {
	coords := _COORD{
		int16(width),
		int16(height),
	}

	return win32ResizePseudoConsole(cpty.hpc, &coords)
}

func (cpty *ConPty) Read(p []byte) (int, error) {
	return cpty.cmdOut.Read(p)
}

func (cpty *ConPty) Write(p []byte) (int, error) {
	return cpty.cmdIn.Write(p)
}

func (cpty *ConPty) Pid() int {
	return int(cpty.pi.ProcessId)
}

type conPtyArgs struct {
	coords  _COORD
	workDir string
	env     []string
}

type ConPtyOption func(args *conPtyArgs)

func ConPtyDimensions(width, height int) ConPtyOption {
	return func(args *conPtyArgs) {
		args.coords.X = int16(width)
		args.coords.Y = int16(height)
	}
}

func ConPtyWorkDir(workDir string) ConPtyOption {
	return func(args *conPtyArgs) {
		args.workDir = workDir
	}
}

func ConPtyEnv(env []string) ConPtyOption {
	return func(args *conPtyArgs) {
		args.env = env
	}
}

// Start a new process specified in `commandLine` and attach a pseudo console using the Windows
// ConPty API. If ConPty is not available, ErrConPtyUnsupported will be returned.
//
// On successful return, an instance of ConPty is returned. You must call Close() on this to release
// any resources associated with the process. To get the exit code of the process, you can call Wait().
func Start(commandLine string, options ...ConPtyOption) (*ConPty, error) {
	if !IsConPtyAvailable() {
		return nil, ErrConPtyUnsupported
	}
	args := &conPtyArgs{
		coords: _COORD{defaultConsoleWidth, defaultConsoleHeight},
	}
	for _, opt := range options {
		opt(args)
	}

	var cmdIn, cmdOut, ptyIn, ptyOut windows.Handle
	if err := windows.CreatePipe(&ptyIn, &cmdIn, nil, 0); err != nil {
		return nil, fmt.Errorf("CreatePipe: %v", err)
	}
	if err := windows.CreatePipe(&cmdOut, &ptyOut, nil, 0); err != nil {
		closeHandles(ptyIn, cmdIn)
		return nil, fmt.Errorf("CreatePipe: %v", err)
	}

	hPc, err := win32CreatePseudoConsole(&args.coords, ptyIn, ptyOut)
	if err != nil {
		closeHandles(ptyIn, ptyOut, cmdIn, cmdOut)
		return nil, err
	}

	pi, err := createConsoleProcessAttachedToPTY(hPc, commandLine, args.workDir, args.env)
	if err != nil {
		closeHandles(ptyIn, ptyOut, cmdIn, cmdOut)
		win32ClosePseudoConsole(hPc)
		return nil, fmt.Errorf("Failed to create console process: %v", err)
	}

	cpty := &ConPty{
		hpc:    hPc,
		pi:     pi,
		ptyIn:  &handleIO{ptyIn},
		ptyOut: &handleIO{ptyOut},
		cmdIn:  &handleIO{cmdIn},
		cmdOut: &handleIO{cmdOut},
	}
	return cpty, nil
}
