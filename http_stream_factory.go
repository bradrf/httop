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
	name := fmt.Sprintf("%s (%s %s)", stype, net, transport)
	reader := tcpreader.NewReaderStream()
	pipeline := h.connTracker.Open(transport.FastHash())
	stream := NewHttpStream(name, stype, reader, pipeline)
	go stream.Process()
	return stream
}
