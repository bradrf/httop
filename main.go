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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 0, "SnapLen for pcap packet capture")
var serverPort = flag.Int("p", 80, "Server port for differentiating HTTP responses from requests")
var additionalFilter = flag.String("f", "", "Additional filter, added to default tcp port filter")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")
var flushMinutes = flag.Int("flush", 5, "Number of minutes to preserve tracking of idle connections")

// TODO: timing for whole start/stop of tcp, and for each http req/resp, both time for resp and time
// to next request (consider good metrics stuff for common stats like mean/max/90th, etc)
var mux sync.Mutex
var tcpConns map[uint64]uint64
var httpStatusCounts map[uint64]uint64
var httpReqBytes uint64
var httpRespBytes uint64

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	name           string
}

type httpClientStream struct {
	httpStream
	requests uint64
}

type httpServerStream struct {
	httpStream
	responses uint64
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	// track each unique connection
	// note: FastHash is guaranteed to match in both directions so we track it only once
	mapInc(tcpConns, transport.FastHash())
	src := int(binary.BigEndian.Uint16(transport.Src().Raw()))
	if src == *serverPort {
		// stream is from the server, so decode HTTP responses...
		server := &httpServerStream{
			httpStream: httpStream{
				net:       net,
				transport: transport,
				r:         tcpreader.NewReaderStream(),
				name:      fmt.Sprintf("server (%s %s)", net, transport),
			},
			responses: 0,
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
			},
			requests: 0,
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
			bodyBytes := uint64(tcpreader.DiscardBytesToEOF(req.Body))
			req.Body.Close()
			log.Println(h.name, "request:", req, "with", bodyBytes)
			atomic.AddUint64(&httpReqBytes, bodyBytes)
			atomic.AddUint64(&h.requests, 1)
		}
	}
}

func (h *httpClientStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	h.r.Reassembled(reassembly)
}

func (h *httpClientStream) ReassemblyComplete() {
	log.Printf("%s closed: requests=%d", h.name, h.requests)
	h.r.ReassemblyComplete()
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
			bodyBytes := uint64(tcpreader.DiscardBytesToEOF(resp.Body))
			resp.Body.Close()
			log.Println(h.name, "response:", resp, "with", bodyBytes)
			atomic.AddUint64(&httpRespBytes, bodyBytes)
			mapInc(httpStatusCounts, uint64(resp.StatusCode))
			atomic.AddUint64(&h.responses, 1)
		}
	}
}

func (h *httpServerStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	h.r.Reassembled(reassembly)
}

func (h *httpServerStream) ReassemblyComplete() {
	log.Printf("%s closed: responses=%d", h.name, h.responses)
	h.r.ReassemblyComplete()
}

func mapInc(m map[uint64]uint64, k uint64) {
	mux.Lock()
	defer mux.Unlock()
	if _, set := m[k]; set {
		m[k] += 1
	} else {
		m[k] = 1
	}
}

func report() {
	log.Printf("connections=%d", len(tcpConns))
	log.Printf("request_body_bytes=%d", httpReqBytes)
	log.Printf("response_body_bytes=%d", httpRespBytes)
	for status, count := range httpStatusCounts {
		log.Printf("%d=%d", status, count)
	}
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

	// Set up metrics
	tcpConns = make(map[uint64]uint64)
	httpStatusCounts = make(map[uint64]uint64)

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
