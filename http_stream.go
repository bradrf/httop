package main

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// Handle decoding of HTTP requests and implement tcpassembly.Stream
type HttpStream struct {
	name          string
	stype         string
	reader        tcpreader.ReaderStream
	httpConn      *HttpConn
	reassembledAt time.Time
}

func NewHttpStream(name string, stype string,
	reader tcpreader.ReaderStream, httpConn *HttpConn) *HttpStream {
	return &HttpStream{
		name:     name,
		stype:    stype,
		reader:   reader,
		httpConn: httpConn,
	}
}

func (h *HttpStream) Process() {
	if h.stype == CLIENT {
		h.processClient()
	} else {
		h.processServer()
	}
}

func (h *HttpStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	first := reassembly[0]
	h.reassembledAt = first.Seen
	if first.Skip != 0 {
		log.Printf("%s skipped %d bytes", h.name, first.Skip)
	}
	if first.Start {
		h.httpConn.StartedAt = h.reassembledAt
	}
	if h.httpConn.StartedAt.IsZero() {
		h.httpConn.StartedAt = h.reassembledAt
		log.Printf("%s unknown when stream was started, using reassembly time", h.name)
	}
	if h.httpConn.Stats == nil {
		h.httpConn.Stats = NewHttpStats(h.httpConn.Name, h.httpConn.StartedAt)
	}
	for _, r := range reassembly {
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
