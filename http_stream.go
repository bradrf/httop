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

const SERVER = "server"
const CLIENT = "client"

// TODO: can we get rid of httpconn? just handle everthing through it?
// TODO: should not be referencing "global" command line option "serverPort"!

// Handle decoding of HTTP requests and implement tcpassembly.Stream
type HttpStream struct {
	name          string
	stype         string
	reader        tcpreader.ReaderStream
	httpConn      *HttpConn
	reassembledAt time.Time
}

func HttpStreamType(transFlow gopacket.Flow) string {
	dstPort := int(binary.BigEndian.Uint16(transFlow.Dst().Raw()))
	srcPort := int(binary.BigEndian.Uint16(transFlow.Src().Raw()))
	if dstPort == *serverPort {
		return CLIENT // requests made to the server port
	}
	if srcPort == *serverPort {
		return SERVER // responses to client requests from the server port
	}
	log.Panic("Frame is not to or from the server port:", transFlow)
	return ""
}

func NewHttpStream(netFlow, transFlow gopacket.Flow, httpConn *HttpConn) *HttpStream {
	stype := HttpStreamType(transFlow)
	stream := &HttpStream{
		name:     fmt.Sprintf("%s (%s %s)", stype, netFlow, transFlow),
		stype:    stype,
		reader:   tcpreader.NewReaderStream(),
		httpConn: httpConn,
	}
	if stype == CLIENT {
		go stream.processClient()
	} else {
		go stream.processServer()
	}
	return stream
}

func (h *HttpStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	h.reassembledAt = reassembly[0].Seen
	for _, r := range reassembly {
		if r.Skip != 0 {
			log.Printf("%s skipped %d bytes", h.name, r.Skip)
		}
		if r.Start {
			h.httpConn.Stats.RecordStart(r.Seen)
		}
		if r.End {
			if h.stype == CLIENT {
				h.httpConn.Stats.RecordClientClose(r.Seen)
			} else {
				h.httpConn.Stats.RecordServerClose(r.Seen)
			}
		}
	}
	h.reader.Reassembled(reassembly)
}

func (h *HttpStream) ReassemblyComplete() {
	h.reader.ReassemblyComplete()
	h.httpConn.Release()
}

//////////////////////////////////////////////////////////////////////

func (h *HttpStream) processClient() {
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
			h.httpConn.RequestTimes.Unshift(now)

			bodyBytes := uint64(tcpreader.DiscardBytesToEOF(req.Body))
			req.Body.Close()
			if *verbose {
				log.Println(h.name, "request:", req, "with", bodyBytes)
			} else if !*quiet {
				ctype := req.Header.Get("content-type")
				log.Println(h.name, req.Method, req.Host, req.URL, bodyBytes, ctype)
			}

			h.httpConn.Stats.RecordRequest(now, bodyBytes)
		}
	}
}

func (h *HttpStream) processServer() {
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

			val := h.httpConn.RequestTimes.Shift()
			var requestedAt time.Time
			if val == nil {
				requestedAt = now
			} else {
				requestedAt = val.(time.Time)
			}

			h.httpConn.Stats.RecordResponse(now, requestedAt, bodyBytes, resp.StatusCode)
		}
	}
}
