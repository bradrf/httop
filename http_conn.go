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
	RefCount     int32
	StartedAt    time.Time
	RequestTimes *Queue // of times when request was sent
	Stats        *HttpStats

	Client HttpStream
	Server HttpStream

	mux        sync.Mutex
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
		onComplete:   onComplete,
	}

	stream := NewHttpStream(netFlow, transFlow, conn.Stats, conn.RequestTimes)
	if stream.StreamType() == CLIENT {
		conn.Client = stream
		conn.Server = NewHttpStream(
			netFlow, Invert(transFlow), conn.Stats, conn.RequestTimes)
	} else {
		conn.Client = NewHttpStream(
			netFlow, Invert(transFlow), conn.Stats, conn.RequestTimes)
		conn.Server = stream
	}

	return conn
}

func Invert(transFlow gopacket.Flow) gopacket.Flow {
	flow, _ := gopacket.FlowFromEndpoints(transFlow.Dst(), transFlow.Src())
	return flow
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

func (h *HttpConn) Use() int32 {
	h.mux.Lock()
	defer h.mux.Unlock()
	h.RefCount++
	return h.RefCount
}

func (h *HttpConn) Release() int32 {
	h.mux.Lock()
	defer h.mux.Unlock()
	h.RefCount--
	if h.RefCount < 1 {
		h.onComplete()
	}
	return h.RefCount
}
