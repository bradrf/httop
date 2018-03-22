package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// associate requests with responses (HTTP 1.1 allows multiple requests outstanding as long as
// responses are returned in the same order; see RFC-2616 section 8.1.2.2 Pipelining)
type ConnTracker struct {
	TotalSeen      uint
	LastPacketSeen time.Time

	conns map[uint64]*HttpConn
	mux   *sync.Mutex

	requestCountStats  *SimpleStats
	responseCountStats *SimpleStats
	idleTime           *SimpleStats
	responseTime       *SimpleStats
	response1XXStats   *SimpleStats
	response2XXStats   *SimpleStats
	response3XXStats   *SimpleStats
	response4XXStats   *SimpleStats
	response5XXStats   *SimpleStats
}

// FIXME: move these into conn tracker!
// keep aggregate stats (average of averages for intervals)

func NewConnTracker() *ConnTracker {
	// Set up aggregate stats

	return &ConnTracker{
		conns: make(map[uint64]*HttpConn),
		mux:   &sync.Mutex{},

		requestCountStats:  NewSimpleStats(),
		responseCountStats: NewSimpleStats(),
		idleTime:           NewSimpleStats(),
		responseTime:       NewSimpleStats(),
		response1XXStats:   NewSimpleStats(),
		response2XXStats:   NewSimpleStats(),
		response3XXStats:   NewSimpleStats(),
		response4XXStats:   NewSimpleStats(),
		response5XXStats:   NewSimpleStats(),
	}
}

func (c *ConnTracker) Open(connName string, bidirectionalKey uint64) *HttpConn {
	c.mux.Lock()
	defer c.mux.Unlock()
	httpConn, set := c.conns[bidirectionalKey]
	if !set {
		c.TotalSeen++
		httpConn = NewHttpConn(connName, c.LastPacketSeen,
			func() { c.Close(bidirectionalKey) })
		c.conns[bidirectionalKey] = httpConn
	}
	httpConn.Use()
	return httpConn
}

// attempt close of a httpConn, cleaning up if no longer referenced and aggregate stats
func (c *ConnTracker) Close(bidirectionalKey uint64) {
	c.mux.Lock()
	defer c.mux.Unlock()
	httpConn := c.conns[bidirectionalKey]
	log.Print(httpConn.Stats)
	delete(c.conns, bidirectionalKey)
	c.requestCountStats.PushUint(httpConn.Stats.RequestCount)
	c.responseCountStats.PushUint(httpConn.Stats.ResponseCount)
	c.idleTime.Push(httpConn.Stats.IdleTime.Mean())
	c.responseTime.Push(httpConn.Stats.ResponseTime.Mean())
	for status, count := range httpConn.Stats.StatusCounts {
		switch status / 100 {
		case 1:
			c.response1XXStats.PushUint(count)
		case 2:
			c.response2XXStats.PushUint(count)
		case 3:
			c.response3XXStats.PushUint(count)
		case 4:
			c.response4XXStats.PushUint(count)
		case 5:
			c.response5XXStats.PushUint(count)
		default:
			log.Println("ERROR: Unknown status found:", status)
		}
	}
}

// FIXME: use passed I/O handle of some kind
// TODO: https://github.com/gizak/termui
func (c *ConnTracker) Report() {
	log.Printf("connections: active=%d total=%d", len(c.conns), c.TotalSeen)
	// log.Println("requests/conn avg:", c.requestCountStats)
	// log.Println("idle avg:", c.idleTime)
	// log.Println("responses/conn avg:", c.responseCountStats)
	// log.Println("waiting avg:", c.responseTime)
	// if c.response1XXStats.Len() > 0 {
	// 	log.Println("  1XX:", c.response1XXStats)
	// }
	// if c.response2XXStats.Len() > 0 {
	// 	log.Println("  2XX:", c.response2XXStats)
	// }
	// if c.response3XXStats.Len() > 0 {
	// 	log.Println("  3XX:", c.response3XXStats)
	// }
	// if c.response4XXStats.Len() > 0 {
	// 	log.Println("  4XX:", c.response4XXStats)
	// }
	// if c.response5XXStats.Len() > 0 {
	// 	log.Println("  5XX:", c.response5XXStats)
	// }
	for _, httpConn := range c.conns {
		if httpConn.Stats != nil {
			fmt.Println(httpConn.Stats.ReportString("[RPT] "))
		}
	}
}
