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
	ProxyKey   string
	ClientID   uint64
	ServerID   uint64
}

type errorMessage struct {
	Msg string
}

type busMessage struct {
	Timeout  time.Duration
	Interval time.Duration
}

type x11RequestMessage struct {
	ChannelType      string
	SingleConnection bool
	AuthProtocol     string
	AuthCookie       string
	ScreenNumber     uint32
}

type agentRequestMessage struct {
	ChannelType string
}

type startMessage struct {
	ID    uint64
	Pty   bool
	Shell bool
	Name  string
	Args  []string
	Cols  int
	Rows  int
	Envs  map[string]string
	X11   *x11RequestMessage
	Agent *agentRequestMessage
}

type exitMessage struct {
	ID       uint64
	ExitCode int
}

type resizeMessage struct {
	ID     uint64
	Cols   int
	Rows   int
	Redraw bool
}

type stderrMessage struct {
	ID uint64
}

type channelMessage struct {
	ChannelType string
	ID          uint64
}

type dialMessage struct {
	Network string
	Addr    string
	Timeout time.Duration
}

type listenMessage struct {
	Network string
	Addr    string
}

type acceptMessage struct {
	ID uint64
}

type udpv1Message struct {
	Addr    string
	Timeout time.Duration
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
		return fmt.Errorf("send command write buffer failed: %v", err)
	}
	return nil
}

func recvCommand(stream net.Conn) (string, error) {
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

func sendMessage(stream net.Conn, msg any) error {
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

func recvMessage(stream net.Conn, msg any) error {
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

func sendError(stream net.Conn, err error) {
	if e := sendMessage(stream, errorMessage{err.Error()}); e != nil {
		trySendErrorMessage("send error [%v] failed: %v", err, e)
	}
}

func sendSuccess(stream net.Conn) error {
	return sendMessage(stream, errorMessage{kNoErrorMsg})
}

func recvError(stream net.Conn) error {
	var errMsg errorMessage
	if err := recvMessage(stream, &errMsg); err != nil {
		return fmt.Errorf("recv error failed: %v", err)
	}
	if errMsg.Msg != kNoErrorMsg {
		return fmt.Errorf("%s", errMsg.Msg)
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
		return fmt.Errorf("send UDPv1 packet write buffer failed: %v", err)
	}
	return nil
}

func recvUDPv1Packet(stream net.Conn) (uint16, []byte, error) {
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, portBuf); err != nil {
		return 0, nil, fmt.Errorf("recv UDPv1 packet read port failed: %v", err)
	}
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return 0, nil, fmt.Errorf("recv UDPv1 packet read length failed: %v", err)
	}
	dataLen := binary.BigEndian.Uint16(lenBuf)
	if dataLen == 0 {
		return 0, nil, fmt.Errorf("recv UDPv1 packet length [%d] invalid", dataLen)
	}
	dataBuf := make([]byte, dataLen)
	if _, err := io.ReadFull(stream, dataBuf); err != nil {
		return 0, nil, fmt.Errorf("recv UDPv1 packet read buffer failed: %v", err)
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
		return nil, fmt.Errorf("kcp smux open stream failed: %v", err)
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
		return nil, fmt.Errorf("quic open stream sync failed: %v", err)
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
		return nil, fmt.Errorf("decode pass [%s] failed: %v", info.Pass, err)
	}
	salt, err := hex.DecodeString(info.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt [%s] failed: %v", info.Pass, err)
	}
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

func newQuicClient(addr string, info *ServerInfo, connectTimeout time.Duration) (udpClient, error) {
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
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, &quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic dail [%s] failed: %v", addr, err)
	}
	return &quicClient{conn}, nil
}
