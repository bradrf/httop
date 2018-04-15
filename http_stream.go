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

// TODO: remove these now that the types are reported and inferred
const SERVER = "server"
const CLIENT = "client"

type HttpStream interface {
	tcpassembly.Stream

	StreamType() string

	StartedAt(time.Time)
	StoppedAt(time.Time)
	KilledAt(time.Time)
}

type HttpStreamOnCompleteFunc func()

type httpStream struct {
	name          string
	reader        tcpreader.ReaderStream
	stats         *HttpStats // shared between client/server
	requestTimes  *Queue     // of times when request was sent (shared between client/server)
	reassembledAt time.Time
	onComplete    HttpStreamOnCompleteFunc
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
	httpStats *HttpStats, requestTimes *Queue, invert bool,
	onComplete HttpStreamOnCompleteFunc) HttpStream {

	if invert {
		netFlow, _ = gopacket.FlowFromEndpoints(netFlow.Dst(), netFlow.Src())
		transFlow, _ = gopacket.FlowFromEndpoints(transFlow.Dst(), transFlow.Src())
	}

	stype := HttpStreamType(transFlow)
	stream := httpStream{
		name:         fmt.Sprintf("%s (%s %s)", stype, netFlow, transFlow),
		reader:       tcpreader.NewReaderStream(),
		stats:        httpStats,
		requestTimes: requestTimes,
		onComplete:   onComplete,
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

// TODO: determine better way to confer type of stream!
func (c *clientHttpStream) StreamType() string {
	return CLIENT
}

func (c *clientHttpStream) StoppedAt(ts time.Time) {
	c.stats.RecordClientClose(ts, false)
}

func (c *clientHttpStream) KilledAt(ts time.Time) {
	c.stats.RecordClientClose(ts, true)
}

func (c *clientHttpStream) start() {
	defer c.onComplete()
	buf := bufio.NewReader(&c.reader)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading", c.name, ":", err)
		} else {
			now := c.reassembledAt
			c.requestTimes.Unshift(now)

			bodyBytes := uint64(tcpreader.DiscardBytesToEOF(req.Body))
			req.Body.Close()
			if *verbose {
				log.Println(c.name, "request:", req, "with", bodyBytes)
			} else if !*quiet {
				ctype := req.Header.Get("content-type")
				log.Println(c.name, req.Method, req.Host, req.URL, bodyBytes, ctype)
			}

			c.stats.RecordRequest(now, bodyBytes)
		}
	}
}

//////////////////////////////////////////////////////////////////////
// SERVER

func (s *serverHttpStream) StreamType() string {
	return SERVER
}

func (s *serverHttpStream) StoppedAt(ts time.Time) {
	s.stats.RecordServerClose(ts, false)
}

func (s *serverHttpStream) KilledAt(ts time.Time) {
	s.stats.RecordServerClose(ts, true)
}

func (s *serverHttpStream) start() {
	defer s.onComplete()
	buf := bufio.NewReader(&s.reader)
	for {
		resp, err := http.ReadResponse(buf, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading", s.name, ":", err)
		} else {
			now := s.reassembledAt

			bodyBytes := uint64(tcpreader.DiscardBytesToEOF(resp.Body))
			resp.Body.Close()

			val := s.requestTimes.Shift()
			var requestedAt time.Time
			if val == nil {
				requestedAt = now
			} else {
				requestedAt = val.(time.Time)
			}
			diff := now.Sub(requestedAt)

			// TODO: seems like it'd be nice to report the associated request here?
			//       might be too verbose (i.e. might want to quell original request...?)

			if *verbose {
				log.Println(
					s.name, "response:", resp, "with", bodyBytes, "took", diff)
			} else if !*quiet {
				ctype := resp.Header.Get("content-type")
				log.Println(s.name, resp.Status, bodyBytes, ctype, diff)
			}

			s.stats.RecordResponse(now, requestedAt, bodyBytes, resp.StatusCode)
		}
	}
}
