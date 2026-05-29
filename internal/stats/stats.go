package stats

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
)

const (
	DefaultFlushInterval = 200 * time.Millisecond
	WindowSize           = 120
	SMAPeriod            = 5
	stopTimeout          = 10 * time.Second
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
	PeekHealth(remoteID string) (RemoteHealth, bool)
}

type pendingUpdate struct {
	requestCount uint64
	bytesSent    uint64
	bytesRecv    uint64
	errorCount   uint64
	egressIP     string
	hostname     string
	country      string
	city         string
	health       RemoteHealth
	hasEgressIP  bool
	hasMetadata  bool
	hasHealth    bool
}

type statUpdate struct {
	typ                     byte
	id                      string
	sent, recv              uint64
	ip                      string
	hostname, country, city string
	health                  RemoteHealth
}

type InMemoryStore struct {
	*RemoteStore
	logger        *slog.Logger
	flushInterval time.Duration
	updateCh      chan statUpdate
	stopCh        chan struct{}
	wg            sync.WaitGroup
	started       atomic.Bool

	window             []WindowStat
	windowIdx          int
	prevTotalRequests  uint64
	prevTotalBytesSent uint64
	prevTotalBytesRecv uint64
	prevTotalErrors    uint64

	smaBuffer     [SMAPeriod]float64
	smaBufferSent [SMAPeriod]float64
	smaBufferRecv [SMAPeriod]float64
	smaBufferErrs [SMAPeriod]float64
	smaIdx        int
	smaCount      int
}

func NewInMemoryStore(logger *slog.Logger) *InMemoryStore {
	return &InMemoryStore{
		RemoteStore:   NewRemoteStore(),
		logger:        logger,
		flushInterval: DefaultFlushInterval,
		updateCh:      make(chan statUpdate, 10000),
		stopCh:        make(chan struct{}),
		window:        make([]WindowStat, WindowSize),
	}
}

func (s *InMemoryStore) Start() {
	if !s.started.CompareAndSwap(false, true) {
		return
	}
	s.wg.Add(1)
	go s.runFlusher()
	s.wg.Add(1)
	go s.runWindowTicker()
}

func (s *InMemoryStore) Stop() {
	if !s.started.CompareAndSwap(true, false) {
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
	case <-time.After(stopTimeout):
	}
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

	requests := float64(agg.TotalRequests - s.prevTotalRequests)
	bytesSent := float64(agg.TotalBytesSent - s.prevTotalBytesSent)
	bytesRecv := float64(agg.TotalBytesRecv - s.prevTotalBytesRecv)
	errors := float64(agg.TotalErrors - s.prevTotalErrors)

	s.smaBuffer[s.smaIdx] = requests
	s.smaBufferSent[s.smaIdx] = bytesSent
	s.smaBufferRecv[s.smaIdx] = bytesRecv
	s.smaBufferErrs[s.smaIdx] = errors

	if s.smaCount < SMAPeriod {
		s.smaCount++
	}

	s.smaIdx = (s.smaIdx + 1) % SMAPeriod

	var sumRequests, sumBytesSent, sumBytesRecv, sumErrors float64
	for i := 0; i < s.smaCount; i++ {
		sumRequests += s.smaBuffer[i]
		sumBytesSent += s.smaBufferSent[i]
		sumBytesRecv += s.smaBufferRecv[i]
		sumErrors += s.smaBufferErrs[i]
	}

	s.window[s.windowIdx] = WindowStat{
		Requests:      sumRequests / float64(s.smaCount),
		BytesSent:     sumBytesSent / float64(s.smaCount),
		BytesRecv:     sumBytesRecv / float64(s.smaCount),
		Errors:        sumErrors / float64(s.smaCount),
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
		case u := <-s.updateCh:
			switch u.typ {
			case 0: // request
				p, ok := pending[u.id]
				if !ok {
					p = &pendingUpdate{}
					pending[u.id] = p
				}
				p.requestCount++
			case 1: // bytes
				p, ok := pending[u.id]
				if !ok {
					p = &pendingUpdate{}
					pending[u.id] = p
				}
				p.bytesSent += u.sent
				p.bytesRecv += u.recv
			case 2: // error
				p, ok := pending[u.id]
				if !ok {
					p = &pendingUpdate{}
					pending[u.id] = p
				}
				p.errorCount++
			case 3: // egressIP
				p, ok := pending[u.id]
				if !ok {
					p = &pendingUpdate{}
					pending[u.id] = p
				}
				p.egressIP = u.ip
				p.hasEgressIP = true
			case 4: // metadata
				p, ok := pending[u.id]
				if !ok {
					p = &pendingUpdate{}
					pending[u.id] = p
				}
				p.hostname = u.hostname
				p.country = u.country
				p.city = u.city
				p.hasMetadata = true
			case 5: // health
				p, ok := pending[u.id]
				if !ok {
					p = &pendingUpdate{}
					pending[u.id] = p
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
		rc := p.requestCount
		bs := p.bytesSent
		br := p.bytesRecv
		ec := p.errorCount
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

func (s *InMemoryStore) sendNonBlocking(update statUpdate) {
	if !s.started.Load() {
		return
	}
	select {
	case s.updateCh <- update:
	default:
		if s.logger != nil {
			s.logger.Warn("stats channel full, dropping update")
		}
	}
}

func (s *InMemoryStore) RecordRequest(remoteID string) {
	s.sendNonBlocking(statUpdate{typ: 0, id: remoteID})
}

func (s *InMemoryStore) RecordBytes(remoteID string, sent, received int64) {
	if !s.started.Load() {
		return
	}
	s.sendNonBlocking(statUpdate{typ: 1, id: remoteID, sent: uint64(sent), recv: uint64(received)})
}

func (s *InMemoryStore) RecordError(remoteID string) {
	s.sendNonBlocking(statUpdate{typ: 2, id: remoteID})
}

func (s *InMemoryStore) SetRemoteEgressIP(remoteID string, ip string) {
	s.sendNonBlocking(statUpdate{typ: 3, id: remoteID, ip: ip})
}

func (s *InMemoryStore) SetRemoteMetadata(remoteID, hostname, country, city string) {
	s.sendNonBlocking(statUpdate{typ: 4, id: remoteID, hostname: hostname, country: country, city: city})
}

func (s *InMemoryStore) SetRemoteHealth(remoteID string, health RemoteHealth) {
	s.sendNonBlocking(statUpdate{typ: 5, id: remoteID, health: health})
}

func (s *InMemoryStore) GetRemoteStats(remoteID string) *RemoteStats {
	return s.RemoteStore.GetOrCreate(remoteID)
}

func (s *InMemoryStore) PeekHealth(remoteID string) (RemoteHealth, bool) {
	return s.RemoteStore.PeekHealth(remoteID)
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
	logger  *slog.Logger
	store   Store
	mullvad mullvad.ServerProvider
	config  Config
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

func NewCollector(logger *slog.Logger, store Store, mullvadProvider mullvad.ServerProvider, config Config) *Collector {
	return &Collector{
		logger:  logger,
		store:   store,
		mullvad: mullvadProvider,
		config:  config,
		stopCh:  make(chan struct{}),
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
	case <-time.After(stopTimeout):
	}
}

func (c *Collector) runHealthChecker(ctx context.Context) {
	defer c.wg.Done()

	c.checkHealth(ctx)

	jitter := time.Duration(rand.Int63n(int64(c.config.HealthCheckInterval)))
	time.Sleep(jitter)

	ticker := time.NewTicker(c.config.HealthCheckInterval)
	defer ticker.Stop()

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

	jitter := time.Duration(rand.Int63n(int64(c.config.EgressIPCheckInterval)))
	time.Sleep(jitter)

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

	c.logger.Debug("starting health check", slog.Int("servers", len(servers)))

	type result struct {
		remoteID string
		hostname string
		country  string
		city     string
		health   RemoteHealth
	}

	const workers = 20
	jobs := make(chan mullvad.Server, len(servers))
	results := make(chan result, len(servers))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range jobs {
				serverCtx, cancel := context.WithTimeout(ctx, c.config.HealthCheckHTTPTimeout)
				currentStats := c.store.GetRemoteStats(s.Hostname)
				health := c.pingServer(serverCtx, s.SOCKS5, s.SOCKSPort, currentStats.Health.ConsecutiveFailures, currentStats.Health.ConsecutiveSuccesses)
				cancel()
				results <- result{remoteID: s.Hostname, hostname: s.Hostname, country: s.Country, city: s.City, health: health}
			}
		}()
	}

	for _, server := range servers {
		select {
		case jobs <- server:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			close(results)
			return
		}
	}
	close(jobs)

	wg.Wait()
	close(results)

	var onlineCount int
	for r := range results {
		c.store.SetRemoteMetadata(r.remoteID, r.hostname, r.country, r.city)
		c.store.SetRemoteHealth(r.remoteID, r.health)
		if r.health.Online {
			onlineCount++
		}
	}

	c.logger.Debug("health check complete", slog.Int("online", onlineCount))
}

func (c *Collector) CheckHealthOne(ctx context.Context) (mullvad.Server, error) {
	servers, err := c.mullvad.FetchMullvadList(ctx)
	if err != nil {
		c.logger.Error("failed to fetch server list for health check", slog.String("error", err.Error()))
		return mullvad.Server{}, err
	}

	c.logger.Debug("quick health check for ready", slog.Int("servers", len(servers)))

	type result struct {
		server mullvad.Server
		health RemoteHealth
	}

	const workers = 50
	jobs := make(chan mullvad.Server, len(servers))
	results := make(chan result, len(servers))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range jobs {
				serverCtx, cancel := context.WithTimeout(ctx, c.config.HealthCheckHTTPTimeout)
				currentStats := c.store.GetRemoteStats(s.Hostname)
				health := c.pingServer(serverCtx, s.SOCKS5, s.SOCKSPort, currentStats.Health.ConsecutiveFailures, currentStats.Health.ConsecutiveSuccesses)
				cancel()
				results <- result{server: s, health: health}
			}
		}()
	}

	for _, server := range servers {
		select {
		case jobs <- server:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			close(results)
			return mullvad.Server{}, ctx.Err()
		}
	}
	close(jobs)

	wg.Wait()
	close(results)

	for r := range results {
		c.store.SetRemoteMetadata(r.server.Hostname, r.server.Hostname, r.server.Country, r.server.City)
		c.store.SetRemoteHealth(r.server.Hostname, r.health)
		if r.health.Online {
			c.logger.Debug("found online server", slog.String("hostname", r.server.Hostname))
			return r.server, nil
		}
	}

	return mullvad.Server{}, fmt.Errorf("no online servers found")
}

func (c *Collector) pingServer(ctx context.Context, socksHost string, socksPort int, currentConsecutiveFailures int, currentConsecutiveSuccesses int) RemoteHealth {
	var tcpPings []int64

	for i := 0; i < c.config.PingCount; i++ {
		latency := c.measureSOCKS5Latency(ctx, socksHost, socksPort)
		if latency > 0 {
			tcpPings = append(tcpPings, latency)
		}
	}

	healthLatency := c.measureSOCKS5Health(ctx, socksHost, socksPort)

	isSuccess := healthLatency > 0

	consecutiveFailures := currentConsecutiveFailures
	consecutiveSuccesses := currentConsecutiveSuccesses
	if isSuccess {
		consecutiveFailures = 0
		consecutiveSuccesses++
	} else {
		consecutiveFailures++
		consecutiveSuccesses = 0
	}

	online := consecutiveFailures < c.config.HealthCheckConsecutiveFailures &&
		(consecutiveSuccesses >= c.config.HealthCheckHealthyThreshold || currentConsecutiveFailures == 0)

	health := RemoteHealth{
		Online:               online,
		HealthLatency:        healthLatency,
		LastCheck:            time.Now(),
		ConsecutiveFailures:  consecutiveFailures,
		ConsecutiveSuccesses: consecutiveSuccesses,
	}

	if len(tcpPings) > 0 {
		var sum int64
		for _, p := range tcpPings {
			sum += p
		}
		health.PingMean = float64(sum) / float64(len(tcpPings))
		health.Ping1ms = tcpPings[0]
		if len(tcpPings) >= 2 {
			health.Ping8ms = tcpPings[1]
		}
	} else if healthLatency > 0 {
		health.PingMean = float64(healthLatency)
	}

	return health
}

func (c *Collector) measureSOCKS5Latency(ctx context.Context, socksHost string, socksPort int) int64 {
	addr := net.JoinHostPort(socksHost, strconv.Itoa(socksPort))

	d := net.Dialer{Timeout: 1 * time.Second}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0
	}
	defer conn.Close()

	return time.Since(start).Milliseconds()
}

func (c *Collector) measureSOCKS5Health(ctx context.Context, socksHost string, socksPort int) int64 {
	socksAddr := net.JoinHostPort(socksHost, strconv.Itoa(socksPort))

	dialer, err := c.mullvad.SOCKS5DialerFromAddr(ctx, socksAddr, c.config.SOCKSDialTimeout)
	if err != nil {
		return 0
	}

	transport := &http.Transport{
		Proxy:               http.ProxyURL(nil),
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			type result struct {
				conn net.Conn
				err  error
			}
			done := make(chan result, 1)
			go func() {
				conn, err := dialer.Dial(network, addr)
				done <- result{conn, err}
			}()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case r := <-done:
				return r.conn, r.err
			}
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   c.config.HealthCheckHTTPTimeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://am.i.mullvad.net/json", nil)
	if err != nil {
		return 0
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0
	}

	return time.Since(start).Milliseconds()
}

func (c *Collector) checkEgressIPs(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, c.config.EgressIPCheckTimeout)
	defer cancel()

	servers, err := c.mullvad.FetchMullvadList(ctx)
	if err != nil {
		c.logger.Error("failed to fetch server list for egress IP check", slog.String("error", err.Error()))
		return
	}

	const workers = 20
	jobs := make(chan mullvad.Server, len(servers))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range jobs {
				c.checkEgressIPForServer(ctx, s.SOCKS5, s.SOCKSPort, s.Hostname, s.Hostname, s.Country, s.City)
			}
		}()
	}

	for _, server := range servers {
		jobs <- server
	}
	close(jobs)
	wg.Wait()
}

func (c *Collector) checkEgressIPForServer(ctx context.Context, socksHost string, socksPort int, remoteID, hostname, country, city string) {
	c.store.SetRemoteMetadata(remoteID, hostname, country, city)

	transport := &http.Transport{
		Proxy:             http.ProxyURL(nil),
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	dialer, err := c.mullvad.SOCKS5DialerFromAddr(ctx, net.JoinHostPort(socksHost, strconv.Itoa(socksPort)), 10*time.Second)
	if err != nil {
		return
	}

	type dialerConn interface {
		Dial(network, addr string) (net.Conn, error)
	}
	dc, ok := dialer.(dialerConn)
	if !ok {
		return
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		type result struct {
			conn net.Conn
			err  error
		}
		done := make(chan result, 1)
		go func() {
			conn, err := dc.Dial(network, addr)
			done <- result{conn, err}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-done:
			return r.conn, r.err
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   c.config.EgressIPCheckHTTPTimeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org?format=text", nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
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
