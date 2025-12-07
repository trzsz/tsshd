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
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

const kNoErrorMsg = "_TSSHD_NO_ERROR_"

// ErrCode is an enumeration for tsshd public errors
type ErrCode int

const (
	// ErrProhibited is an error indicating administratively prohibited
	ErrProhibited ErrCode = iota + 101
)

// String converts the error code to human readable form
func (c ErrCode) String() string {
	switch c {
	case ErrProhibited:
		return "ErrProhibited"
	default:
		return "UnknownError" + strconv.Itoa(int(c))
	}
}

// Error is an tsshd error
type Error struct {
	Code ErrCode
	Msg  string
}

// Error converts the tsshd error to human readable form
func (e *Error) Error() string {
	if e.Code == 0 {
		return e.Msg
	}
	return fmt.Sprintf("%s: %s", e.Code.String(), e.Msg)
}

// ServerInfo includes all information used for client login
type ServerInfo struct {
	Ver        string `json:",omitempty"`
	Port       int    `json:",omitempty"`
	Mode       string `json:",omitempty"`
	Pass       string `json:",omitempty"`
	Salt       string `json:",omitempty"`
	ServerCert string `json:",omitempty"`
	ClientCert string `json:",omitempty"`
	ClientKey  string `json:",omitempty"`
	ProxyKey   string `json:",omitempty"`
	ClientID   uint64 `json:",omitempty"`
	ServerID   uint64 `json:",omitempty"`
}

type errorMessage struct {
	Code ErrCode `json:",omitempty"`
	Msg  string  `json:",omitempty"`
}

type debugMessage struct {
	Msg string `json:",omitempty"`
}

type busMessage struct {
	Timeout  time.Duration `json:",omitempty"`
	Interval time.Duration `json:",omitempty"`
}

type x11RequestMessage struct {
	ChannelType      string `json:",omitempty"`
	SingleConnection bool   `json:",omitempty"`
	AuthProtocol     string `json:",omitempty"`
	AuthCookie       string `json:",omitempty"`
	ScreenNumber     uint32 `json:",omitempty"`
}

type agentRequestMessage struct {
	ChannelType string `json:",omitempty"`
}

type startMessage struct {
	ID    uint64               `json:",omitempty"`
	Pty   bool                 `json:",omitempty"`
	Shell bool                 `json:",omitempty"`
	Name  string               `json:",omitempty"`
	Args  []string             `json:",omitempty"`
	Cols  int                  `json:",omitempty"`
	Rows  int                  `json:",omitempty"`
	Envs  map[string]string    `json:",omitempty"`
	X11   *x11RequestMessage   `json:",omitempty"`
	Agent *agentRequestMessage `json:",omitempty"`
	Subs  string               `json:",omitempty"`
}

type exitMessage struct {
	ID       uint64 `json:",omitempty"`
	ExitCode int    `json:",omitempty"`
}

type quitMessage struct {
	Msg string `json:",omitempty"`
}

type aliveMessage struct {
	Time int64 `json:",omitempty"`
}

type resizeMessage struct {
	ID     uint64 `json:",omitempty"`
	Cols   int    `json:",omitempty"`
	Rows   int    `json:",omitempty"`
	Redraw bool   `json:",omitempty"`
}

type stderrMessage struct {
	ID uint64 `json:",omitempty"`
}

type channelMessage struct {
	ChannelType string `json:",omitempty"`
	ID          uint64 `json:",omitempty"`
}

type dialMessage struct {
	Network string        `json:",omitempty"`
	Addr    string        `json:",omitempty"`
	Timeout time.Duration `json:",omitempty"`
}

type listenMessage struct {
	Network string `json:",omitempty"`
	Addr    string `json:",omitempty"`
}

type acceptMessage struct {
	ID uint64 `json:",omitempty"`
}

type udpv1Message struct {
	Addr    string        `json:",omitempty"`
	Timeout time.Duration `json:",omitempty"`
}

type discardMessage struct {
	DiscardMarker  []byte `json:",omitempty"`
	DiscardedInput []byte `json:",omitempty"`
}

type settingsMessage struct {
	KeepPendingInput *bool `json:",omitempty"`
}

func writeAll(dst io.Writer, data []byte) error {
	m := 0
	l := len(data)
	for m < l {
		n, err := dst.Write(data[m:])
		if err != nil {
			return err
		}
		m += n
	}
	return nil
}

func sendCommand(stream net.Conn, command string) error {
	if len(command) == 0 {
		return fmt.Errorf("send command is empty")
	}
	if len(command) > 255 {
		return fmt.Errorf("send command too long: %s", command)
	}
	buffer := make([]byte, len(command)+1)
	buffer[0] = uint8(len(command))
	copy(buffer[1:], []byte(command))
	if err := writeAll(stream, buffer); err != nil {
		return fmt.Errorf("send command write buffer failed: %w", err)
	}
	return nil
}

func recvCommand(stream net.Conn) (string, error) {
	length := make([]byte, 1)
	if _, err := stream.Read(length); err != nil {
		return "", fmt.Errorf("recv command read length failed: %w", err)
	}
	command := make([]byte, length[0])
	if _, err := io.ReadFull(stream, command); err != nil {
		return "", fmt.Errorf("recv command read buffer failed: %w", err)
	}
	return string(command), nil
}

func sendMessage(stream net.Conn, msg any) error {
	msgBuf, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("send message marshal failed: %w", err)
	}
	buffer := make([]byte, len(msgBuf)+4)
	binary.BigEndian.PutUint32(buffer, uint32(len(msgBuf)))
	copy(buffer[4:], msgBuf)
	if err := writeAll(stream, buffer); err != nil {
		return fmt.Errorf("send message write buffer failed: %w", err)
	}
	return nil
}

func recvMessage(stream net.Conn, msg any) error {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return fmt.Errorf("recv message read length failed: %w", err)
	}
	msgBuf := make([]byte, binary.BigEndian.Uint32(lenBuf))
	if _, err := io.ReadFull(stream, msgBuf); err != nil {
		return fmt.Errorf("recv message read buffer failed: %w", err)
	}
	if err := json.Unmarshal(msgBuf, msg); err != nil {
		return fmt.Errorf("recv message unmarshal failed: %w", err)
	}
	return nil
}

func sendError(stream net.Conn, err error) {
	if e := sendMessage(stream, errorMessage{Msg: err.Error()}); e != nil {
		warning("send error [%v] failed: %v", err, e)
	}
}

func sendErrorCode(stream net.Conn, code ErrCode, msg string) {
	if e := sendMessage(stream, errorMessage{code, msg}); e != nil {
		warning("send error [%d][%v] failed: %v", code, msg, e)
	}
}

func sendSuccess(stream net.Conn) error {
	return sendMessage(stream, errorMessage{Msg: kNoErrorMsg})
}

func recvError(stream net.Conn) error {
	var errMsg errorMessage
	if err := recvMessage(stream, &errMsg); err != nil {
		return fmt.Errorf("recv error failed: %w", err)
	}
	if errMsg.Msg != kNoErrorMsg {
		return &Error{errMsg.Code, errMsg.Msg}
	}
	return nil
}

func sendUDPv1Packet(stream net.Conn, port uint16, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("send UDPv1 packet udp data is empty")
	}
	if len(data) > 0xffff {
		return fmt.Errorf("send UDPv1 packet udp data too long %d", len(data))
	}
	buffer := make([]byte, len(data)+4)
	binary.BigEndian.PutUint16(buffer, uint16(port))
	binary.BigEndian.PutUint16(buffer[2:], uint16(len(data)))
	copy(buffer[4:], data)
	if err := writeAll(stream, buffer); err != nil {
		return fmt.Errorf("send UDPv1 packet write buffer failed: %w", err)
	}
	return nil
}

func recvUDPv1Packet(stream net.Conn) (uint16, []byte, error) {
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, portBuf); err != nil {
		return 0, nil, fmt.Errorf("recv UDPv1 packet read port failed: %w", err)
	}
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return 0, nil, fmt.Errorf("recv UDPv1 packet read length failed: %w", err)
	}
	dataLen := binary.BigEndian.Uint16(lenBuf)
	if dataLen == 0 {
		return 0, nil, fmt.Errorf("recv UDPv1 packet length [%d] invalid", dataLen)
	}
	dataBuf := make([]byte, dataLen)
	if _, err := io.ReadFull(stream, dataBuf); err != nil {
		return 0, nil, fmt.Errorf("recv UDPv1 packet read buffer failed: %w", err)
	}
	return binary.BigEndian.Uint16(portBuf), dataBuf, nil
}

type kcpClient struct {
	session *smux.Session
}

func (c *kcpClient) closeClient() error {
	return c.session.Close()
}

func (c *kcpClient) newStream(connectTimeout time.Duration) (net.Conn, error) {
	stream, err := c.session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("kcp smux open stream failed: %w", err)
	}
	return stream, nil
}

type quicClient struct {
	conn *quic.Conn
}

func (c *quicClient) closeClient() error {
	return c.conn.CloseWithError(0, "")
}

func (c *quicClient) newStream(connectTimeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("quic open stream sync failed: %w", err)
	}
	return &quicStream{stream, c.conn}, err
}

func newUdpClient(addr string, info *ServerInfo, connectTimeout time.Duration) (udpClient, error) {
	switch info.Mode {
	case "":
		return nil, fmt.Errorf("%s", "Please upgrade tsshd")
	case kModeKCP:
		return newKcpClient(addr, info)
	case kModeQUIC:
		return newQuicClient(addr, info, connectTimeout)
	default:
		return nil, fmt.Errorf("unknown tsshd mode: %s", info.Mode)
	}
}

func newKcpClient(addr string, info *ServerInfo) (udpClient, error) {
	pass, err := hex.DecodeString(info.Pass)
	if err != nil {
		return nil, fmt.Errorf("decode pass [%s] failed: %w", info.Pass, err)
	}
	salt, err := hex.DecodeString(info.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt [%s] failed: %w", info.Pass, err)
	}
	key := pbkdf2.Key(pass, salt, 4096, 32, sha1.New)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, fmt.Errorf("new aes block crypt failed: %w", err)
	}
	conn, err := kcp.DialWithOptions(addr, block, 1, 1)
	if err != nil {
		return nil, fmt.Errorf("kcp dial [%s] failed: %w", addr, err)
	}
	conn.SetWindowSize(1024, 1024)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWriteDelay(false)
	session, err := smux.Client(conn, &smuxConfig)
	if err != nil {
		return nil, fmt.Errorf("kcp smux client failed: %w", err)
	}
	return &kcpClient{session}, nil
}

func newQuicClient(addr string, info *ServerInfo, connectTimeout time.Duration) (udpClient, error) {
	serverCert, err := hex.DecodeString(info.ServerCert)
	if err != nil {
		return nil, fmt.Errorf("decode server cert [%s] failed: %w", info.ServerCert, err)
	}
	clientCert, err := hex.DecodeString(info.ClientCert)
	if err != nil {
		return nil, fmt.Errorf("decode client cert [%s] failed: %w", info.ClientCert, err)
	}
	clientKey, err := hex.DecodeString(info.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("decode client key [%s] failed: %w", info.ClientKey, err)
	}

	clientTlsCert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("x509 key pair failed: %w", err)
	}
	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(serverCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientTlsCert},
		RootCAs:      serverCertPool,
		ServerName:   "tsshd",
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, &quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic dail [%s] failed: %w", addr, err)
	}
	return &quicClient{conn}, nil
}
