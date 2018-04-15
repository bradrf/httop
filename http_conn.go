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

	Client *HttpStream
	Server *HttpStream

	mux        sync.Mutex
	onComplete HttpConnOnCompleteFunc
}

func NewHttpConn(packetSeenAt time.Time, network gopacket.NetworkLayer,
	transport gopacket.TransportLayer, onComplete HttpConnOnCompleteFunc) *HttpConn {

	netFlow := network.NetworkFlow()
	tranFlow := transport.TransportFlow()
	name := fmt.Sprintf("%s:%s <=> %s:%s",
		netFlow.Src(), tranFlow.Src(), netFlow.Dst(), tranFlow.Dst())
	conn := &HttpConn{
		Name:         name,
		StartedAt:    packetSeenAt,
		RequestTimes: NewQueue(1),
		Stats:        NewHttpStats(name, packetSeenAt),
		onComplete:   onComplete,
	}
	conn.Client = NewHttpStream(netFlow, tranFlow, conn)
	conn.Server = NewHttpStream(netFlow, tranFlow, conn)
	return conn
}

func (h *HttpConn) Record(packetSeenAt time.Time, tcp *layers.TCP) {
	if tcp.SYN {
		// TODO: record connection started
	} else if tcp.FIN {
		// TODO: record connection stopped
	} else if tcp.RST {
		// TODO: record connection killed
	}
}

func (h *HttpConn) FetchStream(transFlow gopacket.Flow) *HttpStream {
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
