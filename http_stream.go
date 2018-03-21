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
	pipeline      *HttpPipeline
	reassembledAt time.Time
}

func NewHttpStream(name string, stype string,
	reader tcpreader.ReaderStream, pipeline *HttpPipeline) *HttpStream {
	return &HttpStream{
		name:     name,
		stype:    stype,
		reader:   reader,
		pipeline: pipeline,
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
		h.pipeline.StartedAt = h.reassembledAt
	}
	if h.pipeline.StartedAt.IsZero() {
		h.pipeline.StartedAt = h.reassembledAt
		log.Printf("%s unknown when stream was started, using reassembly time", h.name)
	}
	if h.pipeline.Stats == nil {
		h.pipeline.Stats = NewHttpStats(h.pipeline.StartedAt)
	}
	h.reader.Reassembled(reassembly)
}

func (h *HttpStream) ReassemblyComplete() {
	log.Printf("%s closed:\n%s", h.name, h.pipeline.Stats)
	h.reader.ReassemblyComplete()
	h.pipeline.Release()
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
			h.pipeline.RequestTimes.Unshift(now)

			bodyBytes := uint64(tcpreader.DiscardBytesToEOF(req.Body))
			req.Body.Close()
			if *verbose {
				log.Println(h.name, "request:", req, "with", bodyBytes)
			} else if !*quiet {
				ctype := req.Header.Get("content-type")
				log.Println(h.name, req.Method, req.Host, req.URL, bodyBytes, ctype)
			}

			h.pipeline.Stats.RecordRequest(now, bodyBytes)
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

			val := h.pipeline.RequestTimes.Shift()
			var requestedAt time.Time
			if val == nil {
				requestedAt = now
			} else {
				requestedAt = val.(time.Time)
			}

			h.pipeline.Stats.RecordResponse(now, requestedAt, bodyBytes, resp.StatusCode)
		}
	}
}
