package main

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/dgryski/go-onlinestats"
)

type Stats struct {
	Min float64
	Max float64

	format   string
	runStats *onlinestats.Running
}

type HttpStats struct {
	RequestCount          uint         // number of requests made
	ResponseCount         uint         // number of responses made
	RequestBytes          uint64       // sum of all request bodies
	ResponseBytes         uint64       // sum of all response bodies
	ResponseStatusCounts  map[int]uint // type and number of response status codes found
	RequestIntervalStats  *Stats       // track duration from last response to request
	ResponseIntervalStats *Stats       // track duration from last request to response

	mux                sync.Mutex
	lastRequestSentAt  time.Time
	lastResponseSentAt time.Time
}

func NewHttpStats() *HttpStats {
	return &HttpStats{
		ResponseStatusCounts:  make(map[int]uint),
		RequestIntervalStats:  NewStats(3, "s"),
		ResponseIntervalStats: NewStats(3, "s"),
		lastRequestSentAt:     time.Now(),
		lastResponseSentAt:    time.Now(),
	}
}

func (s *HttpStats) RecordRequest(now time.Time, bytes uint64) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.RequestCount++
	s.RequestBytes += bytes
	diff := now.Sub(s.lastResponseSentAt)
	s.RequestIntervalStats.Push(diff.Seconds())
	s.lastRequestSentAt = now
}

func (s *HttpStats) RecordResponse(now time.Time, requestSentAt time.Time, bytes uint64, status int) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.ResponseCount++
	s.ResponseBytes += bytes
	if _, set := s.ResponseStatusCounts[status]; set {
		s.ResponseStatusCounts[status]++
	} else {
		s.ResponseStatusCounts[status] = 1
	}
	diff := now.Sub(requestSentAt)
	s.ResponseIntervalStats.Push(diff.Seconds())
	s.lastResponseSentAt = now
}

func (s *HttpStats) String() string {
	str := fmt.Sprintf("request: count=%d bytes=%d stats=(%s)\n",
		s.RequestCount, s.RequestBytes, s.RequestIntervalStats.String())
	str += fmt.Sprintf("response: count=%d bytes=%d stats=(%s)",
		s.ResponseCount, s.ResponseBytes, s.ResponseIntervalStats.String())
	for status, count := range s.ResponseStatusCounts {
		str += fmt.Sprintf(" %d=%d", status, count)
	}
	return str + "\n"
}

func NewStats(precision int, unit string) *Stats {
	format := fmt.Sprintf(
		"count=%%d min=%%.%df%s mean=%%.%df%s max=%%.%df%s stddev=%%.%df%s",
		precision, unit,
		precision, unit,
		precision, unit,
		precision, unit,
	)
	return &Stats{
		Min:      math.MaxFloat64,
		Max:      math.SmallestNonzeroFloat64,
		format:   format,
		runStats: onlinestats.NewRunning(),
	}
}

func (s *Stats) Push(x float64) {
	if x < s.Min {
		s.Min = x
	}
	if s.Max < x {
		s.Max = x
	}
	s.runStats.Push(x)
}

func (s *Stats) Mean() float64 {
	return s.runStats.Mean()
}

func (s *Stats) Len() int {
	return s.runStats.Len()
}

func (s *Stats) String() string {
	return fmt.Sprintf(s.format,
		s.runStats.Len(), s.Min, s.runStats.Mean(), s.Max, s.runStats.Stddev())
}
