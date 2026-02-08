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
	"context"
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
	"github.com/trzsz/smux"
	"github.com/xtaci/kcp-go/v5"
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
	ServerVer  string `json:",omitempty"`
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
	ProxyMode  string `json:",omitempty"`
}

type errorMessage struct {
	Code ErrCode `json:",omitempty"`
	Msg  string  `json:",omitempty"`
}

type debugMessage struct {
	Msg  string `json:",omitempty"`
	Time int64  `json:",omitempty"`
}

type busMessage struct {
	ClientVer        string        `json:",omitempty"`
	AliveTimeout     time.Duration `json:",omitempty"`
	IntervalTime     time.Duration `json:",omitempty"`
	HeartbeatTimeout time.Duration `json:",omitempty"`
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
	Net     string        `json:",omitempty"`
	Addr    string        `json:",omitempty"`
	Timeout time.Duration `json:",omitempty"`
}

type dialResponse struct {
	errorMessage
	RemoteAddr *net.TCPAddr `json:",omitempty"`
}

func (d *dialResponse) getErrorMessage() *errorMessage {
	return &d.errorMessage
}

type listenMessage struct {
	Net  string `json:",omitempty"`
	Addr string `json:",omitempty"`
}

type acceptMessage struct {
	ID uint64 `json:",omitempty"`
}

type dialUdpMessage struct {
	Net     string        `json:",omitempty"`
	Addr    string        `json:",omitempty"`
	Timeout time.Duration `json:",omitempty"`
}

type dialUdpResponse struct {
	errorMessage
	ID uint64 `json:",omitempty"`
}

type listenUdpMessage struct {
	Net  string `json:",omitempty"`
	Addr string `json:",omitempty"`
}

type acceptUdpMessage struct {
	ID uint64 `json:",omitempty"`
}

func (d *dialUdpResponse) getErrorMessage() *errorMessage {
	return &d.errorMessage
}

type udpReadyMessage struct {
}

type discardMessage struct {
	DiscardMarker  []byte `json:",omitempty"`
	DiscardedInput []byte `json:",omitempty"`
}

type settingsMessage struct {
	KeepPendingInput  *bool `json:",omitempty"`
	KeepPendingOutput *bool `json:",omitempty"`
}

type errorResponder interface {
	getErrorMessage() *errorMessage
}

type rekeyMessage struct {
	PubKey []byte `json:",omitempty"`
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

func sendCommand(stream Stream, command string) error {
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

func recvCommand(stream Stream) (string, error) {
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

func sendMessage(stream Stream, msg any) error {
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

func recvMessage(stream Stream, msg any) error {
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

func sendCommandAndMessage(stream Stream, command string, msg any) error {
	if len(command) == 0 {
		return fmt.Errorf("send command is empty")
	}
	if len(command) > 255 {
		return fmt.Errorf("send command too long: %s", command)
	}

	msgBuf, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("send message marshal failed: %w", err)
	}

	totalLen := 1 + len(command) + 4 + len(msgBuf)
	buffer := make([]byte, totalLen)

	buffer[0] = uint8(len(command))
	copy(buffer[1:], []byte(command))

	binary.BigEndian.PutUint32(buffer[1+len(command):], uint32(len(msgBuf)))
	copy(buffer[1+len(command)+4:], msgBuf)

	if err := writeAll(stream, buffer); err != nil {
		return fmt.Errorf("send command and message failed: %w", err)
	}
	return nil
}

func sendError(stream Stream, err error) {
	if e := sendMessage(stream, errorMessage{Msg: err.Error()}); e != nil {
		warning("send error [%v] failed: %v", err, e)
	}
}

func sendErrorCode(stream Stream, code ErrCode, msg string) {
	if e := sendMessage(stream, errorMessage{code, msg}); e != nil {
		warning("send error [%d][%v] failed: %v", code, msg, e)
	}
}

func sendSuccess(stream Stream) error {
	return sendMessage(stream, errorMessage{Msg: kNoErrorMsg})
}

func recvError(stream Stream) error {
	var errMsg errorMessage
	if err := recvMessage(stream, &errMsg); err != nil {
		return fmt.Errorf("recv error failed: %w", err)
	}
	if errMsg.Msg != kNoErrorMsg {
		return &Error{errMsg.Code, errMsg.Msg}
	}
	return nil
}

func sendResponse(stream Stream, resp errorResponder) error {
	resp.getErrorMessage().Msg = kNoErrorMsg
	return sendMessage(stream, resp)
}

func recvResponse(stream Stream, resp errorResponder) error {
	if err := recvMessage(stream, resp); err != nil {
		return fmt.Errorf("recv response failed: %w", err)
	}
	if errMsg := resp.getErrorMessage(); errMsg.Msg != kNoErrorMsg {
		return &Error{errMsg.Code, errMsg.Msg}
	}
	return nil
}

type protocolClient interface {
	closeClient() error
	getUdpForwarder() *udpForwarder
	handleRekeyEvent(msg *rekeyMessage) error
	newStream(connectTimeout time.Duration) (Stream, error)
}

type kcpClient struct {
	conn      *kcp.UDPSession
	session   *smux.Session
	forwarder *udpForwarder
	crypto    *rotatingCrypto
}

func (c *kcpClient) closeClient() error {
	return c.session.Close()
}

func (c *kcpClient) getUdpForwarder() *udpForwarder {
	return c.forwarder
}

func (c *kcpClient) handleRekeyEvent(msg *rekeyMessage) error {
	return c.crypto.handleClientRekey(msg)
}

func (c *kcpClient) newStream(connectTimeout time.Duration) (Stream, error) {
	stream, err := c.session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("kcp smux open stream failed: %w", err)
	}
	return &smuxStream{stream}, nil
}

type quicClient struct {
	conn      *quic.Conn
	forwarder *udpForwarder
}

func (c *quicClient) closeClient() error {
	return c.conn.CloseWithError(0, "")
}

func (c *quicClient) getUdpForwarder() *udpForwarder {
	return c.forwarder
}

func (c *quicClient) handleRekeyEvent(msg *rekeyMessage) error {
	// rekey is handled by QUIC internally
	return nil
}

func (c *quicClient) newStream(connectTimeout time.Duration) (Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("quic open stream sync failed: %w", err)
	}
	return &quicStream{stream, c.conn}, err
}

func newProtoClient(client *SshUdpClient, opts *UdpClientOptions, addr string) (protocolClient, error) {
	switch opts.ServerInfo.Mode {
	case "":
		return nil, fmt.Errorf("%s", "Please upgrade tsshd")
	case kUdpModeKCP:
		return newKcpClient(client, opts, addr)
	case kUdpModeQUIC:
		return newQuicClient(opts, addr)
	default:
		return nil, fmt.Errorf("unknown tsshd mode: %s", opts.ServerInfo.Mode)
	}
}

func newKcpClient(client *SshUdpClient, opts *UdpClientOptions, addr string) (protocolClient, error) {
	pass, err := hex.DecodeString(opts.ServerInfo.Pass)
	if err != nil {
		return nil, fmt.Errorf("decode pass [%s] failed: %w", opts.ServerInfo.Pass, err)
	}
	salt, err := hex.DecodeString(opts.ServerInfo.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt [%s] failed: %w", opts.ServerInfo.Pass, err)
	}

	crypto, err := newRotatingCrypto(client, pass, salt, kRekeyBytesThreshold, kRekeyTimeThreshold)
	if err != nil {
		return nil, fmt.Errorf("new rotating gcm failed: %w", err)
	}
	block := kcp.NewAEADCrypt(crypto)

	conn, err := kcp.DialWithOptions(addr, block, 1, 1)
	if err != nil {
		return nil, fmt.Errorf("kcp dial [%s] failed: %w", addr, err)
	}
	conn.SetWindowSize(1024, 1024)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWriteDelay(false)

	if opts.ProxyClient != nil {
		conn.SetMtu(int(opts.ProxyClient.GetMaxDatagramSize()))
	} else {
		conn.SetMtu(kDefaultMTU)
	}

	session, err := smux.Client(conn, &smuxConfig)
	if err != nil {
		return nil, fmt.Errorf("kcp smux client failed: %w", err)
	}
	return &kcpClient{conn, session, &udpForwarder{conn: newKcpDatagramConn(conn)}, crypto}, nil
}

func newQuicClient(opts *UdpClientOptions, addr string) (protocolClient, error) {
	serverCert, err := hex.DecodeString(opts.ServerInfo.ServerCert)
	if err != nil {
		return nil, fmt.Errorf("decode server cert [%s] failed: %w", opts.ServerInfo.ServerCert, err)
	}
	clientCert, err := hex.DecodeString(opts.ServerInfo.ClientCert)
	if err != nil {
		return nil, fmt.Errorf("decode client cert [%s] failed: %w", opts.ServerInfo.ClientCert, err)
	}
	clientKey, err := hex.DecodeString(opts.ServerInfo.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("decode client key [%s] failed: %w", opts.ServerInfo.ClientKey, err)
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

	if opts.ProxyClient != nil {
		quicConfig.InitialPacketSize = opts.ProxyClient.GetMaxDatagramSize()
		quicConfig.DisablePathMTUDiscovery = true
	} else {
		quicConfig.InitialPacketSize = kDefaultMTU
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.ConnectTimeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, &quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic dail [%s] failed: %w", addr, err)
	}
	return &quicClient{conn, &udpForwarder{conn: newQuicDatagramConn(conn)}}, nil
}
