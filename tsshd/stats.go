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
	kcp "github.com/trzsz/kcp-go/v5"
)

// TransportStats is a point-in-time snapshot of transport-level statistics
// for a client connection. All counters are int64 and durations are in
// milliseconds so bindings without uint64 support (gomobile) can mirror it.
type TransportStats struct {
	Mode string // kUdpModeKCP or kUdpModeQUIC

	// RTT estimates in milliseconds.
	SRTTMs      int64
	RTTVarMs    int64
	MinRTTMs    int64 // QUIC only (HasMinRTT)
	LatestRTTMs int64 // QUIC only (HasMinRTT)
	RTOMs       int64 // KCP only (HasRTO)

	// Cumulative transport counters.
	// QUIC: protocol-level from quic.ConnectionStats (incl. retransmissions).
	// KCP: UDP wire-level from the client proxy (incl. KCP framing/retrans).
	BytesSent       int64
	BytesReceived   int64
	PacketsSent     int64
	PacketsReceived int64

	// QUIC-only loss accounting (HasLoss). Not monotonic: packets declared
	// lost can subsequently arrive.
	BytesLost   int64
	PacketsLost int64

	// KCP-only retransmitted segments. PROCESS-GLOBAL across every KCP
	// session in this process (RetransIsGlobal), from kcp.DefaultSnmp.
	RetransSegs int64

	HasMinRTT       bool
	HasRTO          bool
	HasLoss         bool
	RetransIsGlobal bool
}

func (c *kcpClient) stats(s *TransportStats) {
	if c == nil {
		return
	}
	s.Mode = kUdpModeKCP
	s.SRTTMs = int64(c.conn.GetSRTT())
	s.RTTVarMs = int64(c.conn.GetSRTTVar())
	s.RTOMs = int64(c.conn.GetRTO())
	s.HasRTO = true
	s.RetransSegs = int64(kcp.DefaultSnmp.Copy().RetransSegs)
	s.RetransIsGlobal = true
	// Byte/packet counters are filled from the client proxy by the caller.
}

func (c *quicClient) stats(s *TransportStats) {
	if c == nil {
		return
	}
	cs := c.conn.ConnectionStats()
	s.Mode = kUdpModeQUIC
	s.SRTTMs = cs.SmoothedRTT.Milliseconds()
	s.RTTVarMs = cs.MeanDeviation.Milliseconds()
	s.MinRTTMs = cs.MinRTT.Milliseconds()
	s.LatestRTTMs = cs.LatestRTT.Milliseconds()
	s.HasMinRTT = true
	s.BytesSent = int64(cs.BytesSent)
	s.BytesReceived = int64(cs.BytesReceived)
	s.PacketsSent = int64(cs.PacketsSent)
	s.PacketsReceived = int64(cs.PacketsReceived)
	s.BytesLost = int64(cs.BytesLost)
	s.PacketsLost = int64(cs.PacketsLost)
	s.HasLoss = true
}

// GetTransportStats returns a snapshot of live transport statistics, or nil
// if the client is closed or has no transport. Safe from any goroutine:
// protoClient and clientProxy are write-once before the client is published,
// and all counters are atomics.
func (c *SshUdpClient) GetTransportStats() *TransportStats {
	if c.closed.Load() || c.protoClient == nil {
		return nil
	}
	s := &TransportStats{}
	c.protoClient.stats(s)
	if s.Mode == kUdpModeKCP && c.clientProxy != nil {
		s.BytesSent = int64(c.clientProxy.cumTraffic.sentBytes.Load())
		s.BytesReceived = int64(c.clientProxy.cumTraffic.recvBytes.Load())
		s.PacketsSent = int64(c.clientProxy.cumTraffic.sentPackets.Load())
		s.PacketsReceived = int64(c.clientProxy.cumTraffic.recvPackets.Load())
	}
	return s
}
