// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var iface = flag.String("i", "en0", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 0, "SnapLen for pcap packet capture")
var serverPort = flag.Int("p", 80, "Server port for differentiating HTTP responses from requests")
var additionalFilter = flag.String("f", "", "Additional filter, added to default tcp port filter")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")
var flushMinutes = flag.Int("flush", 5, "Number of minutes to preserve tracking of idle connections")

type httpPipeline struct {
	requestTimes *Queue // of times when request was reported
	stats        *HttpStats
	refCount     int
}

// associate requests with responses (HTTP 1.1 allows multiple requests outstanding as long as
// responses are returned in the same order; see RFC-2616 section 8.1.2.2 Pipelining)
var tcpConns map[uint64]*httpPipeline
var tcpConnsMux *sync.Mutex

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	name           string
	pipeline       *httpPipeline
}

type httpClientStream struct {
	httpStream
}

type httpServerStream struct {
	httpStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	// track each unique connection
	// note: FastHash is guaranteed to match in both directions so we track it only once
	var pipeline *httpPipeline
	var set bool
	key := transport.FastHash()
	tcpConnsMux.Lock()
	if pipeline, set = tcpConns[key]; set {
		pipeline.refCount++
	} else {
		pipeline = &httpPipeline{
			requestTimes: NewQueue(1),
			stats:        NewHttpStats(),
			refCount:     1,
		}
		tcpConns[key] = pipeline
	}
	fmt.Println("pipeline", pipeline)
	tcpConnsMux.Unlock()

	// set up appropriate decoder...
	src := int(binary.BigEndian.Uint16(transport.Src().Raw()))
	if src == *serverPort {
		// stream is from the server, so decode HTTP responses...
		server := &httpServerStream{
			httpStream: httpStream{
				net:       net,
				transport: transport,
				r:         tcpreader.NewReaderStream(),
				name:      fmt.Sprintf("server (%s %s)", net, transport),
				pipeline:  pipeline,
			},
		}
		go server.process()
		return server
	} else {
		// otherwise, stream is from the client, so decode HTTP requests...
		client := &httpClientStream{
			httpStream: httpStream{
				net:       net,
				transport: transport,
				r:         tcpreader.NewReaderStream(),
				name:      fmt.Sprintf("client (%s %s)", net, transport),
				pipeline:  pipeline,
			},
		}
		go client.process()
		return client
	}
}

func (h *httpClientStream) process() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading", h.name, ":", err)
		} else {
			now := time.Now() // FIXME: use time from pcap!

			bodyBytes := uint64(tcpreader.DiscardBytesToEOF(req.Body))
			req.Body.Close()
			log.Println(h.name, "request:", req, "with", bodyBytes)

			h.pipeline.requestTimes.Unshift(now)
			h.pipeline.stats.RecordRequest(now, bodyBytes)
		}
	}
}

func (h *httpClientStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	h.r.Reassembled(reassembly)
}

func (h *httpClientStream) ReassemblyComplete() {
	log.Printf("%s closed: %s", h.name, h.pipeline.stats) // FIXME: report stats
	h.r.ReassemblyComplete()
	// FIXME: remove if refCount < 1
}

func (h *httpServerStream) process() {
	buf := bufio.NewReader(&h.r)
	for {
		resp, err := http.ReadResponse(buf, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading", h.name, ":", err)
		} else {
			now := time.Now() // FIXME: use time from pcap!

			bodyBytes := uint64(tcpreader.DiscardBytesToEOF(resp.Body))
			resp.Body.Close()
			log.Println(h.name, "response:", resp, "with", bodyBytes)

			val := h.pipeline.requestTimes.Shift()
			var requestedAt time.Time
			if val == nil {
				requestedAt = time.Now() // FIXME: use time from pcap!
			} else {
				requestedAt = val.(time.Time)
			}

			h.pipeline.stats.RecordResponse(now, requestedAt, bodyBytes, resp.StatusCode)
		}
	}
}

func (h *httpServerStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	h.r.Reassembled(reassembly)
}

func (h *httpServerStream) ReassemblyComplete() {
	log.Printf("%s closed: %s", h.name, h.pipeline.stats)
	h.r.ReassemblyComplete()
}

func report() {
	log.Printf("connections=%d", len(tcpConns))
}

func main() {
	flag.Parse()

	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("Starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	filter := "tcp port " + strconv.Itoa(*serverPort)
	if *additionalFilter != "" {
		filter += " and " + *additionalFilter
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	// Set up connection tracking
	tcpConns = make(map[uint64]*httpPipeline)
	tcpConnsMux = &sync.Mutex{}

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	// Issue final report on a normal exit
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		_ = <-sigc
		report()
		os.Exit(0)
	}()

	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if *logAllPackets {
				log.Println(packet)
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			if *flushMinutes > 0 {
				// Every minute, flush connections that haven't seen recent activity.
				diff := time.Duration(0 - *flushMinutes)
				assembler.FlushOlderThan(time.Now().Add(time.Minute * diff))
			}
			report()
		}
	}
}
