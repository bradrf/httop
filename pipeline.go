package main

import (
	"sync"
	"time"
)

type HttpPipelineOnCompleteFunc func()

type HttpPipeline struct {
	RefCount     int32
	StartedAt    time.Time
	RequestTimes *Queue // of times when request was sent
	Stats        *HttpStats

	mux        sync.Mutex
	onComplete HttpPipelineOnCompleteFunc
}

func NewPipeline(onComplete HttpPipelineOnCompleteFunc) *HttpPipeline {
	return &HttpPipeline{
		RequestTimes: NewQueue(1),
		onComplete:   onComplete,
	}
}

func (h *HttpPipeline) Use() int32 {
	h.mux.Lock()
	defer h.mux.Unlock()
	h.RefCount++
	return h.RefCount
}

func (h *HttpPipeline) Release() int32 {
	h.mux.Lock()
	defer h.mux.Unlock()
	h.RefCount--
	if h.RefCount < 1 {
		h.onComplete()
	}
	return h.RefCount
}
