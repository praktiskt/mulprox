package util

import (
	"sync"
)

type SizedWaitGroup struct {
	sem chan struct{}
	wg  sync.WaitGroup
}

func NewSizedWaitGroup(size int) SizedWaitGroup {
	return SizedWaitGroup{
		sem: make(chan struct{}, size),
	}
}

func (s *SizedWaitGroup) Add() {
	s.sem <- struct{}{}
	s.wg.Add(1)
}

func (s *SizedWaitGroup) Done() {
	<-s.sem
	s.wg.Done()
}

func (s *SizedWaitGroup) Wait() {
	s.wg.Wait()
}
