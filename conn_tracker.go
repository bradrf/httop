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

	conns map[uint64]*HttpPipeline
	mux   *sync.Mutex

	requestCountStats  *Stats
	responseCountStats *Stats
	idleStats          *Stats
	waitingStats       *Stats
	response1XXStats   *Stats
	response2XXStats   *Stats
	response3XXStats   *Stats
	response4XXStats   *Stats
	response5XXStats   *Stats
}

// FIXME: move these into conn tracker!
// keep aggregate stats (average of averages for intervals)

func NewConnTracker() *ConnTracker {
	// Set up aggregate stats

	return &ConnTracker{
		conns: make(map[uint64]*HttpPipeline),
		mux:   &sync.Mutex{},

		requestCountStats:  NewStats(CountStatToString),
		responseCountStats: NewStats(CountStatToString),
		idleStats:          NewStats(DurationStatToString),
		waitingStats:       NewStats(DurationStatToString),
		response1XXStats:   NewStats(CountStatToString),
		response2XXStats:   NewStats(CountStatToString),
		response3XXStats:   NewStats(CountStatToString),
		response4XXStats:   NewStats(CountStatToString),
		response5XXStats:   NewStats(CountStatToString),
	}
}

func (c *ConnTracker) Open(bidirectionalKey uint64) *HttpPipeline {
	c.mux.Lock()
	defer c.mux.Unlock()
	pipeline, set := c.conns[bidirectionalKey]
	if !set {
		c.TotalSeen++
		pipeline = NewPipeline(func() { c.Close(bidirectionalKey) })
		c.conns[bidirectionalKey] = pipeline
	}
	pipeline.Use()
	return pipeline
}

// attempt close of a pipeline, cleaning up if no longer referenced and aggregate stats
func (c *ConnTracker) Close(bidirectionalKey uint64) {
	c.mux.Lock()
	defer c.mux.Unlock()
	pipeline := c.conns[bidirectionalKey]
	delete(c.conns, bidirectionalKey)
	c.requestCountStats.PushUint(pipeline.Stats.RequestCount)
	c.responseCountStats.PushUint(pipeline.Stats.ResponseCount)
	c.idleStats.Push(pipeline.Stats.RequestIntervalStats.Mean())
	c.waitingStats.Push(pipeline.Stats.ResponseIntervalStats.Mean())
	for status, count := range pipeline.Stats.ResponseStatusCounts {
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
	log.Println("requests/conn avg:", c.requestCountStats)
	log.Println("idle avg:", c.idleStats)
	log.Println("responses/conn avg:", c.responseCountStats)
	log.Println("waiting avg:", c.waitingStats)
	if c.response1XXStats.Len() > 0 {
		log.Println("  1XX:", c.response1XXStats)
	}
	if c.response2XXStats.Len() > 0 {
		log.Println("  2XX:", c.response2XXStats)
	}
	if c.response3XXStats.Len() > 0 {
		log.Println("  3XX:", c.response3XXStats)
	}
	if c.response4XXStats.Len() > 0 {
		log.Println("  4XX:", c.response4XXStats)
	}
	if c.response5XXStats.Len() > 0 {
		log.Println("  5XX:", c.response5XXStats)
	}
	for _, pipeline := range c.conns {
		fmt.Println(pipeline.Stats)
	}
}
