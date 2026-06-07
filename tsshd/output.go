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
	"bytes"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type clientOutputForwarder struct {
	name         string
	sess         *SshUdpSession
	client       *SshUdpClient
	reader       Stream
	writer       *io.PipeWriter
	marker       atomic.Pointer[[]byte]
	cacheBuf     []byte
	discardLines uint64
	discardBytes uint64
}

func (f *clientOutputForwarder) forward() {
	defer func() {
		_ = f.writer.Close()
		_ = f.reader.CloseRead()
	}()

	buffer := make([]byte, 32*1024)
	for {
		n, err := f.reader.Read(buffer)
		if n > 0 {
			buf := buffer[:n]

			// Check if we need to discard output until a marker is found
			if marker := f.marker.Load(); marker != nil {
				f.cacheBuf = append(f.cacheBuf, buf...)

				if pos := bytes.Index(f.cacheBuf, *marker); pos >= 0 { // Marker found!
					// Record stats for the data BEFORE the marker
					if f.client.discardCallback != nil {
						f.discardLines += uint64(bytes.Count(f.cacheBuf[:pos], []byte("\n")))
						f.discardBytes += uint64(pos)
					}
					// Keep only the data AFTER the marker
					f.cacheBuf = f.cacheBuf[pos+len(*marker):]
					// Safely clear the marker state
					if f.marker.CompareAndSwap(marker, nil) {
						// Add 1 to discardLines to account for the final line fragment before the marker
						lines, bytes := f.discardLines+1, f.discardBytes
						if enableDebugLogging {
							f.client.debug("session [%d] %s matched marker: %s", f.sess.id, f.name, string(*marker))
							if bytes > 0 {
								f.client.debug("discard output %d lines %d bytes", lines, bytes)
							}
						}
						if f.client.discardCallback != nil {
							go f.client.discardCallback(nil, lines, bytes)
						}

						buf = f.cacheBuf
						f.cacheBuf, f.discardLines, f.discardBytes = nil, 0, 0

						if err := writeAll(f.writer, buf); err != nil {
							break
						}
					}
				} else { // Marker NOT found yet.
					// Keep only the tail to handle split markers across reads.
					if keepLen := len(*marker) - 1; len(f.cacheBuf) > keepLen {
						tail := make([]byte, keepLen)
						pos := len(f.cacheBuf) - keepLen
						copy(tail, f.cacheBuf[pos:])
						if f.client.discardCallback != nil {
							f.discardLines += uint64(bytes.Count(f.cacheBuf[:pos], []byte("\n")))
							f.discardBytes += uint64(pos)
						}
						f.cacheBuf = tail
					}
				}
				// Skip normal writing, go read more data
				continue
			}

			// Normal flow: no marker, just write
			if err := writeAll(f.writer, buf); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	f.client.debug("session [%d] %s completed", f.sess.id, f.name)
}

type serverOutputForwarder struct {
	name   string
	sess   *sessionContext
	reader io.Reader
	stream Stream

	handleMutex sync.Mutex
	returned    bool
	writeError  atomic.Bool
	done        chan struct{}
	writeBufCh  chan []byte

	cacheLines       [][]byte
	tmuxOutputPrefix string

	// chHasNewLine ensures the client receives a complete line before further output is cached.
	chHasNewLine bool

	// noNewLineCount records consecutive reads that contain no '\n'.
	// After 3 consecutive reads without newline, output will start being cached.
	// This helps handle cases where some programs may output progress bars or status
	// lines by repeatedly using carriage return ('\r') without emitting newline characters.
	noNewLineCount int

	discardLines   uint64
	discardBytes   uint64
	voidedCapacity uint64

	discardOutput atomic.Bool
	discardMarker atomic.Pointer[[]byte]
}

func (f *serverOutputForwarder) writerLoop() {
	defer func() { _ = f.stream.CloseWrite(); close(f.done) }()
	for buf := range f.writeBufCh {
		if err := writeAll(f.stream, buf); err != nil {
			f.writeError.Store(true)
			warning("write to [%s] failed: %v", f.name, err)
			return
		}
	}
}

func (f *serverOutputForwarder) cacheOutput(buf []byte) {
	for len(buf) > 0 {
		pos := bytes.IndexByte(buf, '\n')
		if pos < 0 {
			pos = bytes.IndexByte(buf, '\r')
		}

		var line []byte
		if pos >= 0 {
			line = buf[:pos+1]
			buf = buf[pos+1:]
		} else {
			line = buf
			buf = nil
		}

		if len(f.cacheLines) == 0 {
			f.cacheLines = append(f.cacheLines, line)
			continue
		}
		last := f.cacheLines[len(f.cacheLines)-1]
		if b := last[len(last)-1]; b != '\n' && (b != '\r' || line[0] == '\n') && len(last) < 1000 {
			f.cacheLines[len(f.cacheLines)-1] = append(last, line...)
			continue
		}
		f.cacheLines = append(f.cacheLines, line)
	}

	maxLines := max(maxPendingOutputLines, f.sess.rows*2)
	if len(f.cacheLines) > maxLines {
		if f.discardLines == 0 {
			f.tmuxOutputPrefix = extractTmuxOutputPrefix(f.cacheLines)
		}

		dropLines := len(f.cacheLines) - maxLines
		f.discardLines += uint64(dropLines)
		for i := range dropLines {
			f.discardBytes += uint64(len(f.cacheLines[i]))
		}
		f.cacheLines = f.cacheLines[dropLines:]

		f.voidedCapacity += uint64(dropLines)
		if f.voidedCapacity > uint64(maxLines) {
			newCacheLines := make([][]byte, len(f.cacheLines), maxLines*2+10)
			copy(newCacheLines, f.cacheLines)
			f.cacheLines = newCacheLines
			f.voidedCapacity = 0
		}
	}
}

func (f *serverOutputForwarder) flushOutput() {
	if len(f.cacheLines) == 0 || f.sess.clientChecker.isTimeout() {
		return
	}

	if f.discardLines > 0 {
		// Output has been discarded due to buffer limits. Attempt to force a screen redraw.
		// If successful (and the session is a PTY), clear the remaining buffered output.
		// The application will repaint the screen, ensuring the client receives a clean state.
		if f.sess.SetSize(0, 0, true, true, nil) == nil {
			f.clearOutput()
			return
		}
	}

	filteredCount := 0
	if enableDebugLogging {
		defer func() {
			if filteredCount > 0 {
				debug("filtered %d ESC[6n cursor position request(s)", filteredCount)
			}
		}()
	}

	for i := -1; i < len(f.cacheLines); i++ {
		var line []byte
		if i < 0 {
			if f.discardLines == 0 {
				continue
			}
			newline := "\r\n"
			if len(f.cacheLines) > 0 && len(f.cacheLines[0]) > 0 && f.cacheLines[0][len(f.cacheLines[0])-1] == '\r' {
				newline = "\r"
			}
			line = fmt.Appendf(nil,
				"\r\033[0;33mWarning: tsshd discarded %d lines %d bytes of output during client disconnection at this point!\033[0m\033[K%s",
				f.discardLines, f.discardBytes, newline)
			if len(f.tmuxOutputPrefix) > 0 {
				line = encodeTmuxOutput(f.tmuxOutputPrefix, line)
			}
		} else {
			line = f.cacheLines[i]
			if enableDebugLogging {
				filteredCount += bytes.Count(line, []byte("\x1b[6n"))
			}
			line = bytes.ReplaceAll(line, []byte("\x1b[6n"), []byte(""))
			if len(line) == 0 {
				continue
			}
		}
	out:
		for {
			select {
			case f.writeBufCh <- line:
				if i < 0 {
					debug("discard old output %d lines %d bytes", f.discardLines, f.discardBytes)
					f.discardLines, f.discardBytes = 0, 0
				}
				break out
			default:
				if f.sess.clientChecker.isTimeout() {
					if i > 0 {
						f.cacheLines = f.cacheLines[i:]
					}
					return
				}
				if f.writeError.Load() {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}

	f.cacheLines, f.chHasNewLine, f.noNewLineCount = nil, false, 0
}

func (f *serverOutputForwarder) clearOutput() {
	f.discardLines += uint64(len(f.cacheLines))
	for _, line := range f.cacheLines {
		f.discardBytes += uint64(len(line))
	}
	if f.discardLines > 0 {
		debug("discard all output %d lines %d bytes", f.discardLines, f.discardBytes)
		if server := f.sess.server.Load(); server != nil {
			msg := &discardMessage{DiscardedOutputLines: f.discardLines, DiscardedOutputBytes: f.discardBytes}
			go func() {
				if err := server.sendBusMessage("discard", msg); err != nil {
					debug("send discard message failed: %v", err)
				}
			}()
		}
	}
	f.discardLines, f.discardBytes = 0, 0
	f.cacheLines, f.chHasNewLine, f.noNewLineCount = nil, false, 0
}

func (f *serverOutputForwarder) onReconnected() {
	f.handleMutex.Lock()
	defer f.handleMutex.Unlock()

	if f.returned {
		return // do not flush after forwardoutput has returned
	}

	f.flushOutput()
}

func (f *serverOutputForwarder) handleBuffer(buf []byte) {
	f.handleMutex.Lock()
	defer f.handleMutex.Unlock()

	// The client requested discarding all previous output.
	// Clear any cached output on the server side and echo the marker
	// back to the client so it can discard any already-delivered data.
	if marker := f.discardMarker.Swap(nil); marker != nil {
		debug("session [%d] %s inject marker: %s", f.sess.id, f.name, string(*marker))

		// Disable server-side discard to prevent conflict,
		// the client will now handle synchronization using the injected marker.
		f.discardOutput.Store(false)

		f.clearOutput()

		buffer := make([]byte, len(*marker)+len(buf))
		copy(buffer, *marker)
		copy(buffer[len(*marker):], buf)
		buf = buffer
	}

	// Discard the cached output exactly once. The flag must be set again for future discards.
	if f.discardOutput.CompareAndSwap(true, false) {
		f.clearOutput()
	}

	if f.chHasNewLine && f.sess.clientChecker.isTimeout() && !f.sess.isKeepPendingOutput() {
		f.cacheOutput(buf)
		return
	}

	if len(f.cacheLines) > 0 {
		f.cacheOutput(buf)
		f.flushOutput()
		return
	}

	var remaining []byte
	if f.sess.clientChecker.isTimeout() && !f.sess.isKeepPendingOutput() {
		pos := bytes.IndexByte(buf, '\n')
		if pos >= 0 {
			remaining = buf[pos+1:]
			buf = buf[:pos+1]
			f.chHasNewLine = true
		} else {
			if f.noNewLineCount < 3 {
				f.noNewLineCount++
			} else {
				f.chHasNewLine = true
				f.cacheOutput(buf)
				return
			}
		}
	}

out:
	for {
		select {
		case f.writeBufCh <- buf:
			break out
		default:
			if f.sess.clientChecker.isTimeout() {
				if f.sess.isKeepPendingOutput() {
					if f.sess.clientChecker.waitUntilReconnected() != nil {
						return
					}
					continue
				}
				select {
				case b := <-f.writeBufCh:
					buf = append(b, buf...)
				default:
				}
				pos := bytes.IndexByte(buf, '\n')
				if pos < 0 && f.noNewLineCount < 3 {
					f.writeBufCh <- buf
					f.noNewLineCount++
					break out
				}

				if pos < 0 {
					f.writeBufCh <- buf
				} else {
					f.writeBufCh <- buf[:pos+1]
					left := buf[pos+1:]
					if len(left) > 0 {
						f.cacheOutput(left)
					}
				}

				f.chHasNewLine = true
				break out
			}
			if f.writeError.Load() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	if len(remaining) > 0 {
		f.cacheOutput(remaining)
	}
}

func (f *serverOutputForwarder) handleError() {
	f.handleMutex.Lock()
	defer f.handleMutex.Unlock()

	for len(f.cacheLines) > 0 && !f.writeError.Load() {
		if f.sess.clientChecker.isTimeout() {
			if f.sess.clientChecker.waitUntilReconnected() != nil {
				break
			}
		}
		f.flushOutput()
	}
}

func (f *serverOutputForwarder) forward() {
	defer func() {
		f.handleMutex.Lock()
		f.returned = true
		close(f.writeBufCh)
		f.handleMutex.Unlock()
		<-f.done
	}()

	go f.writerLoop()

	f.sess.clientChecker.onReconnected(f.onReconnected)

	buffer := make([]byte, 32*1024)
	for {
		n, err := f.reader.Read(buffer)
		if n > 0 {
			buf := make([]byte, n)
			copy(buf, buffer[:n])
			if f.sess.screenBuf != nil {
				select {
				case f.sess.screenBuf <- buf:
				default:
					select {
					case f.sess.screenBuf <- buf:
					case <-time.After(100 * time.Millisecond):
						warning("screen update blocked for 100ms, dropping %d bytes", len(buf))
					}
				}
			}
			f.handleBuffer(buf)
		}
		if err != nil {
			f.handleError()
			break
		}
	}

	debug("session [%d] %s completed", f.sess.id, f.name)
}
