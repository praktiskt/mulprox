package stats

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
)

const (
	DefaultFlushInterval = 50 * time.Millisecond
	WindowSize           = 120
)

type Store interface {
	RecordRequest(remoteID string)
	RecordBytes(remoteID string, sent, received int64)
	RecordError(remoteID string)
	SetRemoteEgressIP(remoteID string, ip string)
	SetRemoteMetadata(remoteID, hostname, country, city string)
	SetRemoteHealth(remoteID string, health RemoteHealth)
	GetRemoteStats(remoteID string) *RemoteStats
	GetAllRemoteStats() []*RemoteStats
	GetAggregatedStats() AggregatedStats
}

type pendingUpdate struct {
	requestCount atomic.Uint64
	bytesSent    atomic.Uint64
	bytesRecv    atomic.Uint64
	errorCount   atomic.Uint64
	egressIP     string
	hostname     string
	country      string
	city         string
	health       RemoteHealth
	hasEgressIP  bool
	hasMetadata  bool
	hasHealth    bool
}

type InMemoryStore struct {
	*RemoteStore
	flushInterval time.Duration
	updateCh      chan interface{}
	stopCh        chan struct{}
	wg            sync.WaitGroup
	started       bool

	window             []WindowStat
	windowIdx          int
	prevTotalRequests  uint64
	prevTotalBytesSent uint64
	prevTotalBytesRecv uint64
	prevTotalErrors    uint64
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		RemoteStore:   NewRemoteStore(),
		flushInterval: DefaultFlushInterval,
		updateCh:      make(chan interface{}, 10000),
		stopCh:        make(chan struct{}),
		window:        make([]WindowStat, WindowSize),
	}
}

func (s *InMemoryStore) Start() {
	if s.started {
		return
	}
	s.started = true
	s.wg.Add(1)
	go s.runFlusher()
	s.wg.Add(1)
	go s.runWindowTicker()
}

func (s *InMemoryStore) Stop() {
	if !s.started {
		return
	}
	close(s.stopCh)
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	s.started = false
}

func (s *InMemoryStore) runFlusher() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.flush()
		case <-s.stopCh:
			s.flush()
			return
		}
	}
}

func (s *InMemoryStore) runWindowTicker() {
	defer s.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.updateWindow()
		case <-s.stopCh:
			return
		}
	}
}

func (s *InMemoryStore) updateWindow() {
	agg := s.RemoteStore.GetAggregated()

	requests := agg.TotalRequests - s.prevTotalRequests
	bytesSent := agg.TotalBytesSent - s.prevTotalBytesSent
	bytesRecv := agg.TotalBytesRecv - s.prevTotalBytesRecv
	errors := agg.TotalErrors - s.prevTotalErrors

	s.window[s.windowIdx] = WindowStat{
		Requests:      requests,
		BytesSent:     bytesSent,
		BytesRecv:     bytesRecv,
		Errors:        errors,
		ActiveRemotes: agg.ActiveRemotes,
		TotalRemotes:  agg.TotalRemotes,
	}

	s.windowIdx = (s.windowIdx + 1) % WindowSize

	s.prevTotalRequests = agg.TotalRequests
	s.prevTotalBytesSent = agg.TotalBytesSent
	s.prevTotalBytesRecv = agg.TotalBytesRecv
	s.prevTotalErrors = agg.TotalErrors
}

func (s *InMemoryStore) flush() {
	pending := make(map[string]*pendingUpdate)

	for {
		select {
		case update := <-s.updateCh:
			switch u := update.(type) {
			case string:
				remoteID := u
				p, ok := pending[remoteID]
				if !ok {
					p = &pendingUpdate{}
					pending[remoteID] = p
				}
				p.requestCount.Add(1)
			case statBytes:
				remoteID := u.remoteID
				p, ok := pending[remoteID]
				if !ok {
					p = &pendingUpdate{}
					pending[remoteID] = p
				}
				p.bytesSent.Add(uint64(u.sent))
				p.bytesRecv.Add(uint64(u.received))
			case stringWithID:
				if u.isError {
					remoteID := u.remoteID
					p, ok := pending[remoteID]
					if !ok {
						p = &pendingUpdate{}
						pending[remoteID] = p
					}
					p.errorCount.Add(1)
				}
			case statEgressIP:
				remoteID := u.remoteID
				p, ok := pending[remoteID]
				if !ok {
					p = &pendingUpdate{}
					pending[remoteID] = p
				}
				p.egressIP = u.ip
				p.hasEgressIP = true
			case statMetadata:
				remoteID := u.remoteID
				p, ok := pending[remoteID]
				if !ok {
					p = &pendingUpdate{}
					pending[remoteID] = p
				}
				p.hostname = u.hostname
				p.country = u.country
				p.city = u.city
				p.hasMetadata = true
			case statHealth:
				remoteID := u.remoteID
				p, ok := pending[remoteID]
				if !ok {
					p = &pendingUpdate{}
					pending[remoteID] = p
				}
				p.health = u.health
				p.hasHealth = true
			}
		default:
			goto apply
		}

		if len(pending) > 10000 {
			goto apply
		}
	}

apply:
	for remoteID, p := range pending {
		rc := p.requestCount.Load()
		bs := p.bytesSent.Load()
		br := p.bytesRecv.Load()
		ec := p.errorCount.Load()
		ip := p.egressIP
		hn := p.hostname
		co := p.country
		ci := p.city
		hh := p.health
		he := p.hasEgressIP
		hm := p.hasMetadata
		hhc := p.hasHealth

		if rc > 0 || bs > 0 || br > 0 || ec > 0 || he || hm || hhc {
			stats := s.GetOrCreate(remoteID)
			if rc > 0 {
				stats.RequestCount.Add(rc)
			}
			if bs > 0 || br > 0 {
				stats.BytesSent.Add(bs)
				stats.BytesRecv.Add(br)
			}
			if ec > 0 {
				stats.ErrorCount.Add(ec)
			}
			if rc > 0 || ec > 0 {
				stats.LastUsed = time.Now()
			}
			if he {
				stats.EgressIP = ip
			}
			if hm {
				stats.Hostname = hn
				stats.Country = co
				stats.City = ci
			}
			if hhc {
				stats.Health = hh
			}
		}
	}
}

type (
	statBytes struct {
		remoteID       string
		sent, received int64
	}
	stringWithID struct {
		remoteID string
		isError  bool
	}
	statEgressIP struct{ remoteID, ip string }
	statMetadata struct{ remoteID, hostname, country, city string }
	statHealth   struct {
		remoteID string
		health   RemoteHealth
	}
)

func (s *InMemoryStore) sendNonBlocking(update interface{}) {
	if !s.started {
		return
	}
	select {
	case s.updateCh <- update:
	default:
	}
}

func (s *InMemoryStore) RecordRequest(remoteID string) {
	s.sendNonBlocking(remoteID)
}

func (s *InMemoryStore) RecordBytes(remoteID string, sent, received int64) {
	s.sendNonBlocking(statBytes{remoteID: remoteID, sent: sent, received: received})
}

func (s *InMemoryStore) RecordError(remoteID string) {
	s.sendNonBlocking(stringWithID{remoteID: remoteID, isError: true})
}

func (s *InMemoryStore) SetRemoteEgressIP(remoteID string, ip string) {
	s.sendNonBlocking(statEgressIP{remoteID: remoteID, ip: ip})
}

func (s *InMemoryStore) SetRemoteMetadata(remoteID, hostname, country, city string) {
	s.sendNonBlocking(statMetadata{remoteID: remoteID, hostname: hostname, country: country, city: city})
}

func (s *InMemoryStore) SetRemoteHealth(remoteID string, health RemoteHealth) {
	s.sendNonBlocking(statHealth{remoteID: remoteID, health: health})
}

func (s *InMemoryStore) GetRemoteStats(remoteID string) *RemoteStats {
	return s.RemoteStore.GetOrCreate(remoteID)
}

func (s *InMemoryStore) GetAllRemoteStats() []*RemoteStats {
	return s.RemoteStore.GetAll()
}

func (s *InMemoryStore) GetAggregatedStats() AggregatedStats {
	agg := s.RemoteStore.GetAggregated()
	agg.Window = s.getWindow()
	return agg
}

func (s *InMemoryStore) getWindow() []WindowStat {
	result := make([]WindowStat, WindowSize)
	for i := 0; i < WindowSize; i++ {
		idx := (s.windowIdx + i) % WindowSize
		result[i] = s.window[idx]
	}
	return result
}

type Collector struct {
	logger     *slog.Logger
	store      Store
	mullvad    *mullvad.Provider
	config     Config
	httpClient *http.Client
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

func NewCollector(logger *slog.Logger, store Store, mullvadProvider *mullvad.Provider, config Config) *Collector {
	return &Collector{
		logger:  logger,
		store:   store,
		mullvad: mullvadProvider,
		config:  config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
}

func (c *Collector) Start(ctx context.Context) {
	c.wg.Add(1)
	go c.runHealthChecker(ctx)

	c.wg.Add(1)
	go c.runEgressIPChecker(ctx)
}

func (c *Collector) Stop() {
	close(c.stopCh)

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func (c *Collector) runHealthChecker(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.HealthCheckInterval)
	defer ticker.Stop()

	c.checkHealth(ctx)

	for {
		select {
		case <-ticker.C:
			c.checkHealth(ctx)
		case <-c.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (c *Collector) runEgressIPChecker(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.EgressIPCheckInterval)
	defer ticker.Stop()

	c.checkEgressIPs(ctx)

	for {
		select {
		case <-ticker.C:
			c.checkEgressIPs(ctx)
		case <-c.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (c *Collector) checkHealth(ctx context.Context) {
	servers, err := c.mullvad.FetchMullvadList(ctx)
	if err != nil {
		c.logger.Error("failed to fetch server list for health check", slog.String("error", err.Error()))
		return
	}

	type result struct {
		remoteID string
		hostname string
		country  string
		city     string
		health   RemoteHealth
	}

	sem := make(chan struct{}, 20)
	results := make(chan result, len(servers))

	for _, server := range servers {
		sem <- struct{}{}
		go func(s mullvad.Server) {
			defer func() { <-sem }()
			health := c.pingServer(ctx, s.SOCKS5, s.SOCKSPort)
			results <- result{remoteID: s.Hostname, hostname: s.Hostname, country: s.Country, city: s.City, health: health}
		}(server)
	}

	for i := 0; i < len(servers); i++ {
		r := <-results
		c.store.SetRemoteMetadata(r.remoteID, r.hostname, r.country, r.city)
		c.store.SetRemoteHealth(r.remoteID, r.health)
	}
}

func (c *Collector) pingServer(ctx context.Context, socksHost string, socksPort int) RemoteHealth {
	var pings []int64
	online := false

	for range c.config.PingTargets {
		latency := c.measureSOCKS5Latency(socksHost, socksPort)
		if latency > 0 {
			pings = append(pings, latency)
			online = true
		}
	}

	health := RemoteHealth{
		Online:    online,
		LastCheck: time.Now(),
	}

	if len(pings) > 0 {
		var sum int64
		for _, p := range pings {
			sum += p
		}
		health.PingMean = float64(sum) / float64(len(pings))

		if len(pings) >= 2 {
			health.Ping1ms = pings[0]
			health.Ping8ms = pings[1]
		}
	}

	return health
}

func (c *Collector) measureSOCKS5Latency(socksHost string, socksPort int) int64 {
	addr := net.JoinHostPort(socksHost, fmt.Sprintf("%d", socksPort))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0
	}
	defer conn.Close()

	return time.Since(start).Milliseconds()
}

func (c *Collector) checkEgressIPs(ctx context.Context) {
	servers, err := c.mullvad.FetchMullvadList(ctx)
	if err != nil {
		c.logger.Error("failed to fetch server list for egress IP check", slog.String("error", err.Error()))
		return
	}

	for _, server := range servers {
		go c.checkEgressIPForServer(ctx, server.SOCKS5, server.SOCKSPort, server.Hostname, server.Hostname, server.Country, server.City)
	}
}

func (c *Collector) checkEgressIPForServer(ctx context.Context, socksHost string, socksPort int, remoteID, hostname, country, city string) {
	c.store.SetRemoteMetadata(remoteID, hostname, country, city)

	transport := &http.Transport{
		Proxy: http.ProxyURL(nil),
	}

	dialer, err := c.mullvad.SOCKS5DialerFromAddr(fmt.Sprintf("%s:%d", socksHost, socksPort), 10*time.Second)
	if err != nil {
		return
	}

	type dialerConn interface {
		Dial(network, addr string) (net.Conn, error)
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.(dialerConn).Dial(network, addr)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	resp, err := client.Get("https://api.ipify.org?format=text")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		ip, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}
		c.store.SetRemoteEgressIP(remoteID, strings.TrimSpace(string(ip)))
	}
}
