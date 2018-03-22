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
	startedAt          time.Time
	lastRequestSentAt  time.Time
	lastResponseSentAt time.Time
}

func NewHttpStats(name string, connectionStartedAt time.Time) *HttpStats {
	return &HttpStats{
		Name:         name,
		StatusCounts: make(map[int]uint),
		IdleTime:     NewSimpleStats(),
		ResponseTime: NewSimpleStats(),

		startedAt:          connectionStartedAt,
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

func (s *HttpStats) ClosedBy() string {
	if !s.ClientClosedAt.IsZero() && s.ClientClosedAt.Sub(s.ServerClosedAt) < 0 {
		return CLIENT
	}
	if !s.ServerClosedAt.IsZero() && s.ServerClosedAt.Sub(s.ClientClosedAt) < 0 {
		return SERVER
	}
	return ""
}

func (s *HttpStats) Age() time.Duration {
	// FIXME: use most recently read packet to track "now"
	now := time.Now()
	return now.Sub(s.startedAt)
}

func (s *HttpStats) ReportString(prefix string) string {
	str := fmt.Sprintf(
		"%s%s: requests=%d responses=%d request_bytes=%d response_bytes=%d age=%s",
		prefix, s.Name, s.RequestCount, s.ResponseCount,
		s.RequestBytes, s.ResponseBytes, s.Age())
	closedBy := s.ClosedBy()
	if closedBy != "" {
		str += fmt.Sprintf("\n%s  closed by %s: client=%s server=%s",
			prefix, closedBy,
			s.ClientClosedAt.Format(time.RFC3339Nano),
			s.ServerClosedAt.Format(time.RFC3339Nano))
	}
	if s.IdleTime.Len() > 0 {
		str += fmt.Sprintf("\n%s  idle time: %s",
			prefix, s.IdleTime.ReportString(DurationStatToString))
	}
	if s.ResponseCount > 0 {
		str += fmt.Sprintf("\n%s  response time: %s",
			prefix, s.ResponseTime.ReportString(DurationStatToString))
		if len(s.StatusCounts) > 0 {
			str += fmt.Sprintf("\n%s  response status:", prefix)
			for status, count := range s.StatusCounts {
				str += fmt.Sprintf(" %d=%d", status, count)
			}
		}
	}
	return str
}

func (s *HttpStats) String() string {
	return s.ReportString("")
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
