package main

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// httpStreamFactory implements tcpassembly.StreamFactory
type HttpStreamFactory struct {
	connTracker *ConnTracker
}

func NewHttpStreamFactory(connTracker *ConnTracker) *HttpStreamFactory {
	return &HttpStreamFactory{connTracker: connTracker}
}

func (h *HttpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	pipeline := h.connTracker.Open(transport.FastHash())
	// set up appropriate decoder...
	src := int(binary.BigEndian.Uint16(transport.Src().Raw()))
	if src == *serverPort {
		// stream is from the server, so decode HTTP responses...
		server := &httpServerStream{
			HttpStream: HttpStream{
				net:       net,
				transport: transport,
				r:         tcpreader.NewReaderStream(),
				name:      fmt.Sprintf("server (%s %s)", net, transport),
				pipeline:  pipeline,
			},
		}
		go server.process()
		return &server.HttpStream
	} else {
		// otherwise, stream is from the client, so decode HTTP requests...
		client := &httpClientStream{
			HttpStream: HttpStream{
				net:       net,
				transport: transport,
				r:         tcpreader.NewReaderStream(),
				name:      fmt.Sprintf("client (%s %s)", net, transport),
				pipeline:  pipeline,
			},
		}
		go client.process()
		return &client.HttpStream
	}
}
