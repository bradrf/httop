package main

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

const SERVER = "server"
const CLIENT = "client"

// implement tcpassembly.StreamFactory
type HttpStreamFactory struct {
	connTracker *ConnTracker
}

func NewHttpStreamFactory(connTracker *ConnTracker) *HttpStreamFactory {
	return &HttpStreamFactory{connTracker: connTracker}
}

func (h *HttpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	var stype string
	src := int(binary.BigEndian.Uint16(transport.Src().Raw()))
	if src == *serverPort {
		stype = SERVER
	} else {
		stype = CLIENT
	}
	httpConnName := fmt.Sprintf("%s:%s <=> %s:%s",
		net.Src(), transport.Src(), net.Dst(), transport.Dst())
	streamName := fmt.Sprintf("%s (%s %s)", stype, net, transport)
	reader := tcpreader.NewReaderStream()
	httpConn := h.connTracker.Open(httpConnName, transport.FastHash())
	stream := NewHttpStream(streamName, stype, reader, httpConn)
	go stream.Process()
	return stream
}
