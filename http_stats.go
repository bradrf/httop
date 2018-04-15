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
	ClosedBy       string       // track who closed and if it was killed with a RST

	mux                sync.Mutex
	sawStart           bool // indicate if we saw the TCP handshake for this connection
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

func (s *HttpStats) RecordStart(now time.Time) {
	s.mux.Lock()
	defer s.mux.Unlock()
	// only set once (i.e. ignore SYN-ACK from server unless we missed the client's SYN)
	if s.startedAt.IsZero() {
		s.startedAt = now
		s.sawStart = true
	}
}

func (s *HttpStats) RecordClientClose(now time.Time, killed bool) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.recordIdle(now)
	s.ClientClosedAt = now
	if s.ClosedBy == "" {
		s.ClosedBy = "client"
		if killed {
			s.ClosedBy += " (killed)"
		}
	}
}

func (s *HttpStats) RecordServerClose(now time.Time, killed bool) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.ServerClosedAt = now
	if s.ClosedBy == "" {
		s.ClosedBy = "server"
		if killed {
			s.ClosedBy += " (killed)"
		}
	}
}

func (s *HttpStats) Age() time.Duration {
	// FIXME: use most recently read packet to track "now"
	now := time.Now()
	return now.Sub(s.startedAt)
}

func (s *HttpStats) ReportString(prefix string) string {
	postAge := ""
	if !s.sawStart {
		postAge = "(missed-start)"
	}
	str := fmt.Sprintf(
		"%s%s: requests=%d responses=%d request_bytes=%d response_bytes=%d age=%s%s",
		prefix, s.Name, s.RequestCount, s.ResponseCount,
		s.RequestBytes, s.ResponseBytes, s.Age(), postAge)
	if s.ClosedBy != "" {
		str += fmt.Sprintf("\n%s  closed by %s: client=%s server=%s",
			prefix, s.ClosedBy,
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
