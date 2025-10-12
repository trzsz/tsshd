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
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

const kNoErrorMsg = "_TSSHD_NO_ERROR_"

type ServerInfo struct {
	Ver        string
	Port       int
	Mode       string
	Pass       string
	Salt       string
	ServerCert string
	ClientCert string
	ClientKey  string
}

type ErrorMessage struct {
	Msg string
}

type BusMessage struct {
	Timeout  time.Duration
	Interval time.Duration
}

type X11Request struct {
	ChannelType      string
	SingleConnection bool
	AuthProtocol     string
	AuthCookie       string
	ScreenNumber     uint32
}

type AgentRequest struct {
	ChannelType string
}

type StartMessage struct {
	ID    uint64
	Pty   bool
	Shell bool
	Name  string
	Args  []string
	Cols  int
	Rows  int
	Envs  map[string]string
	X11   *X11Request
	Agent *AgentRequest
}

type ExitMessage struct {
	ID       uint64
	ExitCode int
}

type ResizeMessage struct {
	ID   uint64
	Cols int
	Rows int
}

type StderrMessage struct {
	ID uint64
}

type ChannelMessage struct {
	ChannelType string
	ID          uint64
}

type DialMessage struct {
	Network string
	Addr    string
	Timeout time.Duration
}

type ListenMessage struct {
	Network string
	Addr    string
}

type AcceptMessage struct {
	ID uint64
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

func SendCommand(stream net.Conn, command string) error {
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
		return fmt.Errorf("send command write buffer failed: %v", err)
	}
	return nil
}

func RecvCommand(stream net.Conn) (string, error) {
	length := make([]byte, 1)
	if _, err := stream.Read(length); err != nil {
		return "", fmt.Errorf("recv command read length failed: %v", err)
	}
	command := make([]byte, length[0])
	if _, err := io.ReadFull(stream, command); err != nil {
		return "", fmt.Errorf("recv command read buffer failed: %v", err)
	}
	return string(command), nil
}

func SendMessage(stream net.Conn, msg any) error {
	msgBuf, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("send message marshal failed: %v", err)
	}
	buffer := make([]byte, len(msgBuf)+4)
	binary.BigEndian.PutUint32(buffer, uint32(len(msgBuf)))
	copy(buffer[4:], msgBuf)
	if err := writeAll(stream, buffer); err != nil {
		return fmt.Errorf("send message write buffer failed: %v", err)
	}
	return nil
}

func RecvMessage(stream net.Conn, msg any) error {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return fmt.Errorf("recv message read length failed: %v", err)
	}
	msgBuf := make([]byte, binary.BigEndian.Uint32(lenBuf))
	if _, err := io.ReadFull(stream, msgBuf); err != nil {
		return fmt.Errorf("recv message read buffer failed: %v", err)
	}
	if err := json.Unmarshal(msgBuf, msg); err != nil {
		return fmt.Errorf("recv message unmarshal failed: %v", err)
	}
	return nil
}

func SendError(stream net.Conn, err error) {
	if e := SendMessage(stream, ErrorMessage{err.Error()}); e != nil {
		trySendErrorMessage("send error [%v] failed: %v", err, e)
	}
}

func SendSuccess(stream net.Conn) error {
	return SendMessage(stream, ErrorMessage{kNoErrorMsg})
}

func RecvError(stream net.Conn) error {
	var errMsg ErrorMessage
	if err := RecvMessage(stream, &errMsg); err != nil {
		return fmt.Errorf("recv error failed: %v", err)
	}
	if errMsg.Msg != kNoErrorMsg {
		return fmt.Errorf("%s", errMsg.Msg)
	}
	return nil
}

type Client interface {
	Close() error
	Reconnect() error
	NewStream() (net.Conn, error)
}

type kcpClient struct {
	session *smux.Session
}

func (c *kcpClient) Close() error {
	return c.session.Close()
}

func (c *kcpClient) Reconnect() error {
	return fmt.Errorf("KCP mode does not support reconnection")
}

func (c *kcpClient) NewStream() (net.Conn, error) {
	stream, err := c.session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("kcp smux open stream failed: %v", err)
	}
	return stream, nil
}

type quicClient struct {
	conn      *quic.Conn
	transport *quic.Transport
}

func (c *quicClient) Close() error {
	err1 := c.conn.CloseWithError(0, "")
	err2 := c.transport.Close()
	err3 := c.transport.Conn.Close()
	if err1 != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("close failed: %v, %v, %v", err1, err2, err3)
	}
	return nil
}

func (c *quicClient) Reconnect() error {
	transport, err := newQuicTransport()
	if err != nil {
		return fmt.Errorf("new quic transport failed: %v", err)
	}
	path, err := c.conn.AddPath(transport)
	if err != nil {
		return fmt.Errorf("quic add path failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := path.Probe(ctx); err != nil {
		return fmt.Errorf("quic path probe failed: %v", err)
	}
	if err := path.Switch(); err != nil {
		return fmt.Errorf("quic path switch failed: %v", err)
	}
	_ = c.transport.Close()
	_ = c.transport.Conn.Close()
	c.transport = transport
	return nil
}

func (c *quicClient) NewStream() (net.Conn, error) {
	stream, err := c.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, fmt.Errorf("quic open stream sync failed: %v", err)
	}
	return &quicStream{stream, c.conn}, err
}

func NewClient(host string, info *ServerInfo) (Client, error) {
	switch info.Mode {
	case "":
		return nil, fmt.Errorf("Please upgrade tsshd.")
	case kModeKCP:
		return newKcpClient(host, info)
	case kModeQUIC:
		return newQuicClient(host, info)
	default:
		return nil, fmt.Errorf("unknown tsshd mode: %s", info.Mode)
	}
}

func newKcpClient(host string, info *ServerInfo) (Client, error) {
	pass, err := hex.DecodeString(info.Pass)
	if err != nil {
		return nil, fmt.Errorf("decode pass [%s] failed: %v", info.Pass, err)
	}
	salt, err := hex.DecodeString(info.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt [%s] failed: %v", info.Pass, err)
	}
	addr := joinHostPort(host, info.Port)
	key := pbkdf2.Key(pass, salt, 4096, 32, sha1.New)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, fmt.Errorf("new aes block crypt failed: %v", err)
	}
	conn, err := kcp.DialWithOptions(addr, block, 10, 3)
	if err != nil {
		return nil, fmt.Errorf("kcp dial [%s] failed: %v", addr, err)
	}
	conn.SetNoDelay(1, 10, 2, 1)
	session, err := smux.Client(conn, &smuxConfig)
	if err != nil {
		return nil, fmt.Errorf("kcp smux client failed: %v", err)
	}
	return &kcpClient{session}, nil
}

func newQuicClient(host string, info *ServerInfo) (Client, error) {
	serverCert, err := hex.DecodeString(info.ServerCert)
	if err != nil {
		return nil, fmt.Errorf("decode server cert [%s] failed: %v", info.ServerCert, err)
	}
	clientCert, err := hex.DecodeString(info.ClientCert)
	if err != nil {
		return nil, fmt.Errorf("decode client cert [%s] failed: %v", info.ClientCert, err)
	}
	clientKey, err := hex.DecodeString(info.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("decode client key [%s] failed: %v", info.ClientKey, err)
	}

	clientTlsCert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("x509 key pair failed: %v", err)
	}
	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(serverCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientTlsCert},
		RootCAs:      serverCertPool,
		ServerName:   "tsshd",
	}
	addr := joinHostPort(host, info.Port)
	transport, err := newQuicTransport()
	if err != nil {
		return nil, fmt.Errorf("new quic transport failed: %v", err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr [%s] failed: %v", addr, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := transport.Dial(ctx, udpAddr, tlsConfig, &quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic transport dail [%s] failed: %v", addr, err)
	}
	return &quicClient{conn, transport}, nil
}

func newQuicTransport() (*quic.Transport, error) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp failed: %v", err)
	}
	return &quic.Transport{Conn: udpConn}, nil
}

func joinHostPort(host string, port int) string {
	if !strings.HasPrefix(host, "[") && strings.ContainsRune(host, ':') {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
