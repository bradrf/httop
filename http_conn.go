package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type HttpConnOnCompleteFunc func()

// manages both the server and client HTTP streams
type HttpConn struct {
	Name         string
	StartedAt    time.Time
	RequestTimes *Queue // of times when request was sent
	Stats        *HttpStats

	Client HttpStream
	Server HttpStream

	mux        sync.Mutex
	refCount   int
	onComplete HttpConnOnCompleteFunc
}

func NewHttpConn(packetSeenAt time.Time, network gopacket.NetworkLayer,
	transport gopacket.TransportLayer, onComplete HttpConnOnCompleteFunc) *HttpConn {

	netFlow := network.NetworkFlow()
	transFlow := transport.TransportFlow()
	name := fmt.Sprintf("%s:%s <=> %s:%s",
		netFlow.Src(), transFlow.Src(), netFlow.Dst(), transFlow.Dst())

	conn := &HttpConn{
		Name:         name,
		StartedAt:    packetSeenAt,
		RequestTimes: NewQueue(1),
		Stats:        NewHttpStats(name, packetSeenAt),
		refCount:     2,
		onComplete:   onComplete,
	}

	stream := NewHttpStream(
		netFlow, transFlow, conn.Stats, conn.RequestTimes, false, conn.release)

	if stream.StreamType() == CLIENT {
		conn.Client = stream
		conn.Server = NewHttpStream(
			netFlow, transFlow, conn.Stats, conn.RequestTimes, true, conn.release)
	} else {
		conn.Client = NewHttpStream(
			netFlow, transFlow, conn.Stats, conn.RequestTimes, true, conn.release)
		conn.Server = stream
	}

	return conn
}

func (h *HttpConn) Record(packetSeenAt time.Time, transport gopacket.TransportLayer) {
	stream := h.FetchStream(transport.TransportFlow())
	tcp := transport.(*layers.TCP)
	if tcp.SYN {
		stream.StartedAt(packetSeenAt)
	} else if tcp.FIN {
		stream.StoppedAt(packetSeenAt)
	} else if tcp.RST {
		stream.KilledAt(packetSeenAt)
	}
}

func (h *HttpConn) FetchStream(transFlow gopacket.Flow) HttpStream {
	stype := HttpStreamType(transFlow)
	if stype == CLIENT {
		return h.Client
	}
	return h.Server
}

func (h *HttpConn) release() {
	h.mux.Lock()
	defer h.mux.Unlock()
	h.refCount--
	if h.refCount < 1 {
		h.onComplete()
	}
}
