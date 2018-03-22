package main

import (
	"sync"
	"time"
)

type HttpConnOnCompleteFunc func()

type HttpConn struct {
	Name         string
	RefCount     int32
	StartedAt    time.Time
	RequestTimes *Queue // of times when request was sent
	Stats        *HttpStats

	mux        sync.Mutex
	onComplete HttpConnOnCompleteFunc
}

func NewHttpConn(name string, onComplete HttpConnOnCompleteFunc) *HttpConn {
	return &HttpConn{
		Name:         name,
		RequestTimes: NewQueue(1),
		onComplete:   onComplete,
	}
}

func (h *HttpConn) Use() int32 {
	h.mux.Lock()
	defer h.mux.Unlock()
	h.RefCount++
	return h.RefCount
}

func (h *HttpConn) Release() int32 {
	h.mux.Lock()
	defer h.mux.Unlock()
	h.RefCount--
	if h.RefCount < 1 {
		h.onComplete()
	}
	return h.RefCount
}
