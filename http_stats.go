package main

import (
	"fmt"
	"sync"
	"time"
)

type StatToStringFunc func(float64) string

type HttpStats struct {
	Name           string       // name of connection
	RequestCount   uint         // number of requests
	ResponseCount  uint         // number of responses
	RequestBytes   uint64       // sum of all request bodies
	ResponseBytes  uint64       // sum of all response bodies
	StatusCounts   map[int]uint // type and number of status codes found
	IdleTime       *SimpleStats // track how much time was spent not waiting for a response
	ResponseTime   *SimpleStats // track how much time was spent waiting for a response
	ClientClosedAt time.Time    // time when client closed the connection
	ServerClosedAt time.Time    // time when server closed the connection

	mux                sync.Mutex
	lastRequestSentAt  time.Time
	lastResponseSentAt time.Time
}

func NewHttpStats(name string, connectionStartedAt time.Time) *HttpStats {
	return &HttpStats{
		Name:         name,
		StatusCounts: make(map[int]uint),
		IdleTime:     NewSimpleStats(),
		ResponseTime: NewSimpleStats(),

		lastRequestSentAt:  connectionStartedAt,
		lastResponseSentAt: connectionStartedAt,
	}
}

func (s *HttpStats) RecordRequest(now time.Time, bytes uint64) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.RequestCount++
	s.RequestBytes += bytes
	s.recordIdle(now)
	s.lastRequestSentAt = now
}

func (s *HttpStats) RecordResponse(now time.Time, requestSentAt time.Time, bytes uint64, status int) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.ResponseCount++
	s.ResponseBytes += bytes
	if _, set := s.StatusCounts[status]; set {
		s.StatusCounts[status]++
	} else {
		s.StatusCounts[status] = 1
	}
	diff := now.Sub(requestSentAt)
	s.ResponseTime.PushDuration(diff)
	s.lastResponseSentAt = now
}

func (s *HttpStats) RecordClientClose(now time.Time) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.recordIdle(now)
	s.ClientClosedAt = now
}

func (s *HttpStats) RecordServerClose(now time.Time) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.ServerClosedAt = now
}

func (s *HttpStats) String() string {
	str := s.Name + ":\n"
	if !s.ClientClosedAt.IsZero() || !s.ServerClosedAt.IsZero() {
		str += fmt.Sprintf("  closed: client=%s server=%s\n",
			s.ClientClosedAt.Format(time.RFC3339),
			s.ServerClosedAt.Format(time.RFC3339))
	}
	str += fmt.Sprintf("  idle time: bytes=%d %s\n",
		s.RequestBytes, s.IdleTime.ReportString(DurationStatToString))
	str += fmt.Sprintf("  response time: bytes=%d %s\n",
		s.ResponseBytes, s.ResponseTime.ReportString(DurationStatToString))
	str += "  response status:"
	for status, count := range s.StatusCounts {
		str += fmt.Sprintf(" %d=%d", status, count)
	}
	return str + "\n"
}

func (s *HttpStats) recordIdle(now time.Time) {
	diff := s.lastRequestSentAt.Sub(s.lastResponseSentAt)
	if diff > 0 {
		// last request is newer than last response...still waiting for the response
		return
	}
	diff = now.Sub(s.lastResponseSentAt)
	s.IdleTime.PushDuration(diff)
}
