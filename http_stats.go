package main

import (
	"fmt"
	"sync"
	"time"
)

type StatToStringFunc func(float64) string

type HttpStats struct {
	RequestCount  uint         // number of requests
	ResponseCount uint         // number of responses
	RequestBytes  uint64       // sum of all request bodies
	ResponseBytes uint64       // sum of all response bodies
	StatusCounts  map[int]uint // type and number of response status codes found
	IdleTimes     *SimpleStats // track how much time was spent not waiting for a response
	ResponseTimes *SimpleStats // track how much time was spent waiting for a response
	ClosedBy      string       // indicate who initiated closing the connection

	mux                sync.Mutex
	lastRequestSentAt  time.Time
	lastResponseSentAt time.Time
}

func NewHttpStats(connectionStartedAt time.Time) *HttpStats {
	return &HttpStats{
		StatusCounts:  make(map[int]uint),
		IdleTimes:     NewSimpleStats(),
		ResponseTimes: NewSimpleStats(),

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
	s.ResponseTimes.PushDuration(diff)
	s.lastResponseSentAt = now
}

func (s *HttpStats) RecordClientClose(now time.Time) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.recordIdle(now)
	s.ClosedBy = CLIENT
}

func (s *HttpStats) RecordServerClose(now time.Time) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.recordIdle(now)
	s.ClosedBy = SERVER
}

func (s *HttpStats) String() string {
	str := fmt.Sprintf("idle time: bytes=%d stats=(%s)\n",
		s.RequestBytes, s.IdleTimes.ReportString(DurationStatToString))
	str += fmt.Sprintf("response time: bytes=%d stats=(%s)",
		s.ResponseBytes, s.ResponseTimes.ReportString(DurationStatToString))
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
	s.IdleTimes.PushDuration(diff)
}
