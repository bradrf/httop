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
		RequestIntervalStats:  NewStats(),
		ResponseIntervalStats: NewStats(),
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

func NewStats() *Stats {
	return &Stats{
		Min:      math.MaxFloat64,
		Max:      math.SmallestNonzeroFloat64,
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
	min := s.Min * 1000
	mean := s.runStats.Mean() * 1000
	max := s.Max * 1000
	stddev := s.runStats.Stddev() * 1000
	return fmt.Sprintf("min=%.1fms mean=%.1fms max=%.1fms stddev=%.1fms",
		min, mean, max, stddev)
}
