package main

import "sync"

type Queue struct {
	mux   *sync.Mutex
	nodes []interface{}
}

func NewQueue(size int) *Queue {
	return &Queue{
		mux:   &sync.Mutex{},
		nodes: make([]interface{}, 0, size),
	}
}

func (q *Queue) Unshift(n interface{}) {
	q.mux.Lock()
	defer q.mux.Unlock()
	q.nodes = append(q.nodes, n)
}

func (q *Queue) Shift() interface{} {
	q.mux.Lock()
	defer q.mux.Unlock()
	var n interface{}
	if len(q.nodes) > 0 {
		n = q.nodes[0]
		q.nodes = q.nodes[1:]
	} else {
		n = nil
	}
	return n
}
