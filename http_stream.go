package main

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// Handle decoding of HTTP requests and implements tcpassembly.Stream
type HttpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	name           string
	pipeline       *HttpPipeline
}

type httpClientStream struct {
	HttpStream
}

type httpServerStream struct {
	HttpStream
}

//////////////////////////////////////////////////////////////////////

func (h *HttpStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	first := reassembly[0]
	if first.Skip != 0 {
		log.Printf("%s skipped %d bytes", h.name, first.Skip)
	}
	if first.Start {
		h.pipeline.StartedAt = first.Seen
	}
	if h.pipeline.StartedAt.IsZero() {
		// FIXME: h.pipeline.StartedAt = lastPacketSeen
		h.pipeline.StartedAt = time.Now()
		log.Printf("%s unknown when stream was started, using last seen packet time", h.name)
	}
	h.pipeline.Stats = NewHttpStats(h.pipeline.StartedAt)
	h.r.Reassembled(reassembly)
}

func (h *HttpStream) ReassemblyComplete() {
	log.Printf("%s closed:\n%s", h.name, h.pipeline.Stats)
	h.r.ReassemblyComplete()
	h.pipeline.Release()
}

//////////////////////////////////////////////////////////////////////

func (h *httpClientStream) process() {
	now := time.Now() // FIXME: use time from pcap!
	h.pipeline.RequestTimes.Unshift(now)

	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading", h.name, ":", err)
		} else {
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

func (h *httpServerStream) process() {
	now := time.Now() // FIXME: use time from pcap!
	buf := bufio.NewReader(&h.r)
	for {
		resp, err := http.ReadResponse(buf, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading", h.name, ":", err)
		} else {
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
				requestedAt = now // FIXME: use time from pcap!
			} else {
				requestedAt = val.(time.Time)
			}

			h.pipeline.Stats.RecordResponse(now, requestedAt, bodyBytes, resp.StatusCode)
		}
	}
}
