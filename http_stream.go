package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// Handle decoding of HTTP requests and responses

const SERVER = "server"
const CLIENT = "client"

type HttpStream interface {
	tcpassembly.Stream

	StartedAt(time.Time)
	StoppedAt(time.Time)
	KilledAt(time.Time)
}

type httpStream struct {
	name          string
	reader        tcpreader.ReaderStream
	stats         *HttpStats
	requestTimes  *Queue // of times when request was sent
	reassembledAt time.Time
}

type clientHttpStream struct {
	httpStream
}

type serverHttpStream struct {
	httpStream
}

//////////////////////////////////////////////////////////////////////

func HttpStreamType(transFlow gopacket.Flow) string {
	dstPort := int(binary.BigEndian.Uint16(transFlow.Dst().Raw()))
	srcPort := int(binary.BigEndian.Uint16(transFlow.Src().Raw()))
	// TODO: should not be referencing "global" command line option "serverPort"!
	if dstPort == *serverPort {
		return CLIENT // requests made to the server port
	}
	if srcPort == *serverPort {
		return SERVER // responses to client requests from the server port
	}
	log.Panic("Flow does not include the server port:", transFlow)
	return ""
}

func NewHttpStream(netFlow, transFlow gopacket.Flow,
	httpStats *HttpStats, requestTimes *Queue) HttpStream {

	stype := HttpStreamType(transFlow)
	stream := httpStream{
		name:         fmt.Sprintf("%s (%s %s)", stype, netFlow, transFlow),
		reader:       tcpreader.NewReaderStream(),
		stats:        httpStats,
		requestTimes: requestTimes,
	}

	if stype == CLIENT {
		client := &clientHttpStream{httpStream: stream}
		go client.start()
		return client
	} else {
		server := &serverHttpStream{httpStream: stream}
		go server.start()
		return server
	}
}

func (h *httpStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	h.reassembledAt = reassembly[0].Seen
	h.reader.Reassembled(reassembly)
}

func (h *httpStream) ReassemblyComplete() {
	h.reader.ReassemblyComplete()
}

func (h *httpStream) StartedAt(ts time.Time) {
	h.stats.RecordStart(ts)
}

//////////////////////////////////////////////////////////////////////
// CLIENT

func (h *clientHttpStream) StoppedAt(ts time.Time) {
	h.stats.RecordClientClose(ts, false)
}

func (h *clientHttpStream) KilledAt(ts time.Time) {
	h.stats.RecordClientClose(ts, true)
}

func (h *clientHttpStream) start() {
	buf := bufio.NewReader(&h.reader)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading", h.name, ":", err)
		} else {
			now := h.reassembledAt
			h.requestTimes.Unshift(now)

			bodyBytes := uint64(tcpreader.DiscardBytesToEOF(req.Body))
			req.Body.Close()
			if *verbose {
				log.Println(h.name, "request:", req, "with", bodyBytes)
			} else if !*quiet {
				ctype := req.Header.Get("content-type")
				log.Println(h.name, req.Method, req.Host, req.URL, bodyBytes, ctype)
			}

			h.stats.RecordRequest(now, bodyBytes)
		}
	}
}

//////////////////////////////////////////////////////////////////////
// SERVER

func (h *serverHttpStream) StoppedAt(ts time.Time) {
	h.stats.RecordServerClose(ts, false)
}

func (h *serverHttpStream) KilledAt(ts time.Time) {
	h.stats.RecordServerClose(ts, true)
}

func (h *serverHttpStream) start() {
	buf := bufio.NewReader(&h.reader)
	for {
		resp, err := http.ReadResponse(buf, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading", h.name, ":", err)
		} else {
			now := h.reassembledAt

			bodyBytes := uint64(tcpreader.DiscardBytesToEOF(resp.Body))
			resp.Body.Close()

			if *verbose {
				log.Println(h.name, "response:", resp, "with", bodyBytes)
			} else if !*quiet {
				ctype := resp.Header.Get("content-type")
				log.Println(h.name, resp.Status, bodyBytes, ctype)
			}

			val := h.requestTimes.Shift()
			var requestedAt time.Time
			if val == nil {
				requestedAt = now
			} else {
				requestedAt = val.(time.Time)
			}

			h.stats.RecordResponse(now, requestedAt, bodyBytes, resp.StatusCode)
		}
	}
}
