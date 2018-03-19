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

// TODO: add idle stats (or, maybe just rename request intervals as idle...)
// make it clear that the aggregates are stats per tcp connection.
// probably also should report overall counts for 2xx, etc

// TODO: report client IP from [0] of x-forward-for headers...

// ubuntu@ip-172-26-4-144:~/httop$ GOPATH=`pwd` go build -a -ldflags '-extldflags "-static"' -o httop.linux64

var iface = flag.String("i", "en6", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
var serverPort = flag.Int("p", 80, "Server port for differentiating HTTP responses from requests")
var additionalFilter = flag.String("f", "", "Additional filter, added to default tcp port filter")
var verbose = flag.Bool("v", false, "Logs full HTTP request and response (with headers, etc.)")
var quiet = flag.Bool("q", false, "Restrict logs to only close and summary reports")
var flushMinutes = flag.Int("flush", 5, "Number of minutes to preserve tracking of idle connections")

type httpPipeline struct {
	requestTimes *Queue // of times when request was reported
	stats        *HttpStats
	key          uint64
	refCount     int
}

// associate requests with responses (HTTP 1.1 allows multiple requests outstanding as long as
// responses are returned in the same order; see RFC-2616 section 8.1.2.2 Pipelining)
var tcpConns map[uint64]*httpPipeline
var tcpConnsMux *sync.Mutex
var totalConns uint

// keep aggregate stats (average of averages for intervals)
var requestCountStats *Stats
var responseCountStats *Stats
var requestIntervalStats *Stats
var responseIntervalStats *Stats
var response1XXStats *Stats
var response2XXStats *Stats
var response3XXStats *Stats
var response4XXStats *Stats
var response5XXStats *Stats

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests and implements tcpassembly.Stream
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

// attempt close of a pipeline, cleaning up if no more ref counts and adding in the aggregate stats
func (p *httpPipeline) Close() {
	tcpConnsMux.Lock()
	defer tcpConnsMux.Unlock()
	p.refCount--
	if p.refCount > 0 {
		return
	}
	delete(tcpConns, p.key)
	requestCountStats.PushUint(p.stats.RequestCount)
	responseCountStats.PushUint(p.stats.ResponseCount)
	requestIntervalStats.Push(p.stats.RequestIntervalStats.Mean())
	responseIntervalStats.Push(p.stats.ResponseIntervalStats.Mean())
	for status, count := range p.stats.ResponseStatusCounts {
		switch status / 100 {
		case 1:
			response1XXStats.PushUint(count)
		case 2:
			response2XXStats.PushUint(count)
		case 3:
			response3XXStats.PushUint(count)
		case 4:
			response4XXStats.PushUint(count)
		case 5:
			response5XXStats.PushUint(count)
		default:
			log.Println("ERROR: Unknown status found:", status)
		}
	}
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
		totalConns++
		pipeline = &httpPipeline{
			requestTimes: NewQueue(1),
			stats:        NewHttpStats(),
			key:          key,
			refCount:     1,
		}
		tcpConns[key] = pipeline
	}
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
	now := time.Now() // FIXME: use time from pcap!
	h.pipeline.requestTimes.Unshift(now)

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
			h.pipeline.stats.RecordRequest(now, bodyBytes)
		}
	}
}

func (h *httpClientStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	h.r.Reassembled(reassembly)
}

func (h *httpClientStream) ReassemblyComplete() {
	log.Printf("%s closed:\n%s", h.name, h.pipeline.stats)
	h.r.ReassemblyComplete()
	h.pipeline.Close()
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

			val := h.pipeline.requestTimes.Shift()
			var requestedAt time.Time
			if val == nil {
				requestedAt = now // FIXME: use time from pcap!
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
	log.Printf("%s closed:\n%s", h.name, h.pipeline.stats)
	h.r.ReassemblyComplete()
	h.pipeline.Close()
}

func report() {
	log.Printf("connections: active=%d total=%d", len(tcpConns), totalConns)
	log.Println("request stats:")
	log.Println("  counts:", requestCountStats)
	log.Println("  intervals:", requestIntervalStats)
	log.Println("response stats:")
	log.Println("  counts:", responseCountStats)
	log.Println("  intervals:", responseIntervalStats)
	if response1XXStats.Len() > 0 {
		log.Println("  1XX:", response1XXStats)
	}
	if response2XXStats.Len() > 0 {
		log.Println("  2XX:", response2XXStats)
	}
	if response3XXStats.Len() > 0 {
		log.Println("  3XX:", response3XXStats)
	}
	if response4XXStats.Len() > 0 {
		log.Println("  4XX:", response4XXStats)
	}
	if response5XXStats.Len() > 0 {
		log.Println("  5XX:", response5XXStats)
	}
}

func main() {
	flag.Parse()

	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	if *fname != "" {
		// FIXME: need to support reading time from pcap before we allow this...
		log.Panic("Not supported")
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

	// Set up aggregate stats
	requestCountStats = NewStats(CountStatToString)
	responseCountStats = NewStats(CountStatToString)
	requestIntervalStats = NewStats(DurationStatToString)
	responseIntervalStats = NewStats(DurationStatToString)
	response1XXStats = NewStats(CountStatToString)
	response2XXStats = NewStats(CountStatToString)
	response3XXStats = NewStats(CountStatToString)
	response4XXStats = NewStats(CountStatToString)
	response5XXStats = NewStats(CountStatToString)

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
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil ||
				packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				// log.Println("Ignoring unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp,
				packet.Metadata().Timestamp)

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
