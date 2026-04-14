package util

type SizedWaitGroup struct {
	sem   chan struct{}
	ready chan struct{}
}

func NewSizedWaitGroup(size int) SizedWaitGroup {
	return SizedWaitGroup{
		sem:   make(chan struct{}, size),
		ready: make(chan struct{}),
	}
}

func (s *SizedWaitGroup) Add() {
	s.sem <- struct{}{}
}

func (s *SizedWaitGroup) Done() {
	<-s.sem
}

func (s *SizedWaitGroup) Wait() {
	for i := 0; i < cap(s.sem); i++ {
		s.sem <- struct{}{}
	}
	close(s.ready)
}
