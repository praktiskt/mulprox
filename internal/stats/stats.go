package stats

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
)

type Store interface {
	RecordRequest(remoteID string)
	RecordBytes(remoteID string, sent, received int64)
	RecordLatency(remoteID string, latency time.Duration)
	RecordError(remoteID string)
	SetRemoteEgressIP(remoteID string, ip string)
	SetRemoteMetadata(remoteID, hostname, country, city string)
	SetRemoteHealth(remoteID string, health RemoteHealth)
	GetRemoteStats(remoteID string) *RemoteStats
	GetAllRemoteStats() []*RemoteStats
	GetAggregatedStats() AggregatedStats
}

type InMemoryStore struct {
	*RemoteStore
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		RemoteStore: NewRemoteStore(),
	}
}

func (s *InMemoryStore) RecordRequest(remoteID string) {
	stats := s.GetOrCreate(remoteID)
	stats.mu.Lock()
	stats.RequestCount++
	stats.LastUsed = time.Now()
	stats.mu.Unlock()
}

func (s *InMemoryStore) RecordBytes(remoteID string, sent, received int64) {
	stats := s.GetOrCreate(remoteID)
	stats.mu.Lock()
	stats.BytesSent += uint64(sent)
	stats.BytesRecv += uint64(received)
	stats.mu.Unlock()
}

func (s *InMemoryStore) RecordLatency(remoteID string, latency time.Duration) {
	stats := s.GetOrCreate(remoteID)
	stats.mu.Lock()
	stats.LatencySum += latency
	stats.LatencyCount++
	stats.mu.Unlock()
}

func (s *InMemoryStore) RecordError(remoteID string) {
	stats := s.GetOrCreate(remoteID)
	stats.mu.Lock()
	stats.ErrorCount++
	stats.mu.Unlock()
}

func (s *InMemoryStore) SetRemoteEgressIP(remoteID string, ip string) {
	stats := s.GetOrCreate(remoteID)
	stats.mu.Lock()
	stats.EgressIP = ip
	stats.mu.Unlock()
}

func (s *InMemoryStore) SetRemoteMetadata(remoteID, hostname, country, city string) {
	stats := s.GetOrCreate(remoteID)
	stats.mu.Lock()
	stats.Hostname = hostname
	stats.Country = country
	stats.City = city
	stats.mu.Unlock()
}

func (s *InMemoryStore) SetRemoteHealth(remoteID string, health RemoteHealth) {
	stats := s.GetOrCreate(remoteID)
	stats.mu.Lock()
	stats.Health = health
	stats.mu.Unlock()
}

func (s *InMemoryStore) GetRemoteStats(remoteID string) *RemoteStats {
	return s.GetOrCreate(remoteID)
}

func (s *InMemoryStore) GetAllRemoteStats() []*RemoteStats {
	return s.RemoteStore.GetAll()
}

func (s *InMemoryStore) GetAggregatedStats() AggregatedStats {
	return s.RemoteStore.GetAggregated()
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
		health   RemoteHealth
	}

	sem := make(chan struct{}, 20)
	results := make(chan result, len(servers))

	for _, server := range servers {
		sem <- struct{}{}
		go func(s mullvad.Server) {
			defer func() { <-sem }()
			health := c.pingServer(ctx, s.SOCKS5, s.SOCKSPort)
			results <- result{remoteID: s.Hostname, health: health}
		}(server)
	}

	for i := 0; i < len(servers); i++ {
		r := <-results
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
	addr := fmt.Sprintf("%s:%d", socksHost, socksPort)

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
		go c.checkEgressIPForServer(ctx, server.SOCKS5, server.SOCKSPort, server.Hostname)
	}
}

func (c *Collector) checkEgressIPForServer(ctx context.Context, socksHost string, socksPort int, remoteID string) {
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
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		ip := string(buf[:n])
		c.store.SetRemoteEgressIP(remoteID, ip)
	}
}
