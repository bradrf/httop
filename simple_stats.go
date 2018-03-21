package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/dgryski/go-onlinestats"
)

type SimpleStats struct {
	*onlinestats.Running
	min   float64
	max   float64
	total float64
}

type SimpleStatsReport struct {
	Count  int
	Min    float64
	Mean   float64
	Max    float64
	Stddev float64
	Total  float64
}

type SimpleStatToStringFunc func(float64) string

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

func NewSimpleStats() *SimpleStats {
	return &SimpleStats{
		Running: onlinestats.NewRunning(),
		min:     math.MaxFloat64,
		max:     -math.SmallestNonzeroFloat64,
	}
}

func (s *SimpleStats) PushDuration(x time.Duration) {
	s.Push(float64(x.Nanoseconds()))
}

func (s *SimpleStats) PushUint64(x uint64) {
	s.Push(float64(x))
}

func (s *SimpleStats) PushUint(x uint) {
	s.Push(float64(x))
}

func (s *SimpleStats) Push(x float64) {
	if x < s.min {
		s.min = x
	}
	if s.max < x {
		s.max = x
	}
	s.total += x
	s.Running.Push(x)
}

func (s *SimpleStats) Report() *SimpleStatsReport {
	return &SimpleStatsReport{
		Count:  s.Len(),
		Min:    s.min,
		Mean:   s.Mean(),
		Max:    s.max,
		Stddev: s.Stddev(),
		Total:  s.total,
	}
}

func (s *SimpleStats) ReportString(toString SimpleStatToStringFunc) string {
	rpt := s.Report()
	return fmt.Sprintf("count=%d min=%s mean=%s max=%s stddev=%s total=%s",
		rpt.Count, toString(rpt.Min), toString(rpt.Mean),
		toString(rpt.Stddev), toString(rpt.Max), toString(rpt.Total))
}

func (s *SimpleStats) ToJson() string {
	json, err := json.Marshal(s.Report())
	if err == nil {
		return string(json)
	}
	return fmt.Sprintf("{\"error\":\"%v\"}", err)
}

func (s *SimpleStats) String() string {
	return fmt.Sprintf("%v", s.Report())
}
