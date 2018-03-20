package main

import (
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/dgryski/go-onlinestats"
)

type StatToStringFunc func(float64) string

type Stats struct {
	Min float64
	Max float64

	toString StatToStringFunc
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

func DurationStatToString(x float64) string {
	if math.IsNaN(x) {
		return "NaN"
	}
	return time.Duration(x).String()
}

func CountStatToString(x float64) string {
	if math.IsNaN(x) {
		return "NaN"
	}
	return strconv.FormatUint(uint64(x), 10)
}

func NewHttpStats(startedAt time.Time) *HttpStats {
	return &HttpStats{
		ResponseStatusCounts:  make(map[int]uint),
		RequestIntervalStats:  NewStats(DurationStatToString),
		ResponseIntervalStats: NewStats(DurationStatToString),
		lastRequestSentAt:     startedAt,
		lastResponseSentAt:    startedAt,
	}
}

func (s *HttpStats) RecordRequest(now time.Time, bytes uint64) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.RequestCount++
	s.RequestBytes += bytes
	diff := now.Sub(s.lastResponseSentAt)
	s.RequestIntervalStats.PushDuration(diff)
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
	s.ResponseIntervalStats.PushDuration(diff)
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

func NewStats(statToString StatToStringFunc) *Stats {
	return &Stats{
		Min:      math.MaxFloat64,
		Max:      -math.SmallestNonzeroFloat64,
		toString: statToString,
		runStats: onlinestats.NewRunning(),
	}
}

func (s *Stats) PushDuration(x time.Duration) {
	s.Push(float64(x.Nanoseconds()))
}

func (s *Stats) PushUint64(x uint64) {
	s.Push(float64(x))
}

func (s *Stats) PushUint(x uint) {
	s.Push(float64(x))
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
	if s.Len() < 1 {
		return fmt.Sprintf("count=0")
	}
	return fmt.Sprintf("count=%d min=%s mean=%s max=%s stddev=%s",
		s.runStats.Len(), s.toString(s.Min), s.toString(s.runStats.Mean()),
		s.toString(s.Max), s.toString(s.runStats.Stddev()))
}
