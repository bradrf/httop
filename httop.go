package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

// TODO: add idle stats (or, maybe just rename request intervals as idle...)
// make it clear that the aggregates are stats per tcp connection.
// probably also should report overall counts for 2xx, etc

// TODO: report client IP from [0] of x-forward-for headers...

// ubuntu@ip-172-26-4-144:~/httop$ GOPATH=`pwd` go build -a -ldflags '-extldflags "-static"' -o httop.linux64

var iface = flag.String("i", "eth0", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
var serverPort = flag.Int("p", 80, "Server port for differentiating HTTP responses from requests")
var additionalFilter = flag.String("f", "", "Additional filter, added to default tcp port filter")
var verbose = flag.Bool("v", false, "Logs full HTTP request and response (with headers, etc.)")
var quiet = flag.Bool("q", false, "Restrict logs to only close and summary reports")
var flushMinutes = flag.Int("flush", 5, "Number of minutes to preserve tracking of idle connections")
var delaySeconds = flag.Int("delay", 5, "Number of seconds to wait between connection reports")

func main() {
	flag.Parse()

	var handle *pcap.Handle
	var err error
	var msg string

	if *fname != "" {
		msg = fmt.Sprintf("Reading from %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		msg = fmt.Sprintf("Capturing from %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	filter := "tcp port " + strconv.Itoa(*serverPort)
	if *additionalFilter != "" {
		filter += " and " + *additionalFilter
	}
	log.Printf("%s filtered by %q", msg, filter)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	connTracker := NewConnTracker()
	streamFactory := NewHttpStreamFactory(connTracker)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	flushDuration := time.Duration(*flushMinutes) * time.Minute
	flushTicker := time.Tick(time.Duration(1) * time.Minute)
	reportTicker := time.Tick(time.Duration(*delaySeconds) * time.Second)

	// Issue final report on a normal exit
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		_ = <-sigc
		connTracker.Report()
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
			connTracker.LastPacketSeen = packet.Metadata().Timestamp
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp,
				packet.Metadata().Timestamp)

		case <-flushTicker:
			if *flushMinutes > 0 {
				// Every minute, flush connections that haven't seen recent activity.
				oldAt := time.Now().Add(-flushDuration)
				assembler.FlushOlderThan(oldAt)
			}
		case <-reportTicker:
			connTracker.Report()
		}
	}
}
