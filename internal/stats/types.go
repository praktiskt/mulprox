package stats

import (
	"sync"
	"time"
)

type RemoteHealth struct {
	Ping1ms   int64     `json:"ping_1ms"`
	Ping8ms   int64     `json:"ping_8ms"`
	PingMean  float64   `json:"ping_mean"`
	Online    bool      `json:"online"`
	LastCheck time.Time `json:"last_check"`
}

type RemoteStats struct {
	mu           sync.Mutex    `json:"-"`
	RemoteID     string        `json:"remote_id"`
	Hostname     string        `json:"hostname"`
	Country      string        `json:"country"`
	City         string        `json:"city"`
	EgressIP     string        `json:"egress_ip"`
	RequestCount uint64        `json:"request_count"`
	BytesSent    uint64        `json:"bytes_sent"`
	BytesRecv    uint64        `json:"bytes_recv"`
	ErrorCount   uint64        `json:"error_count"`
	LatencySum   time.Duration `json:"latency_sum"`
	LatencyCount uint64        `json:"latency_count"`
	Health       RemoteHealth  `json:"health"`
	LastUsed     time.Time     `json:"last_used"`
	CreatedAt    time.Time     `json:"created_at"`
}

type AggregatedStats struct {
	TotalRequests     uint64            `json:"total_requests"`
	TotalBytesSent    uint64            `json:"total_bytes_sent"`
	TotalBytesRecv    uint64            `json:"total_bytes_recv"`
	TotalErrors       uint64            `json:"total_errors"`
	ActiveRemotes     int               `json:"active_remotes"`
	TotalRemotes      int               `json:"total_remotes"`
	OnlineRemotes     int               `json:"online_remotes"`
	RequestsPerRemote map[string]uint64 `json:"requests_per_remote"`
}

type Config struct {
	HealthCheckInterval   time.Duration
	PingTargets           []string
	EgressIPCheckInterval time.Duration
}

func DefaultConfig() Config {
	return Config{
		HealthCheckInterval:   30 * time.Second,
		PingTargets:           []string{"1.1.1.1", "8.8.8.8"},
		EgressIPCheckInterval: 5 * time.Minute,
	}
}

type RemoteStore struct {
	mu      sync.RWMutex
	remotes map[string]*RemoteStats
}

func NewRemoteStore() *RemoteStore {
	return &RemoteStore{
		remotes: make(map[string]*RemoteStats),
	}
}

func (s *RemoteStore) GetOrCreate(remoteID string) *RemoteStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	if stats, ok := s.remotes[remoteID]; ok {
		return stats
	}

	stats := &RemoteStats{
		RemoteID:  remoteID,
		CreatedAt: time.Now(),
	}
	s.remotes[remoteID] = stats
	return stats
}

func (s *RemoteStore) GetAll() []*RemoteStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*RemoteStats, 0, len(s.remotes))
	for _, stats := range s.remotes {
		result = append(result, stats)
	}
	return result
}

func (s *RemoteStore) GetAggregated() AggregatedStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var agg AggregatedStats
	agg.RequestsPerRemote = make(map[string]uint64)

	for _, rs := range s.remotes {
		agg.TotalRequests += rs.RequestCount
		agg.TotalBytesSent += rs.BytesSent
		agg.TotalBytesRecv += rs.BytesRecv
		agg.TotalErrors += rs.ErrorCount
		if rs.RequestCount > 0 {
			agg.ActiveRemotes++
		}
		agg.RequestsPerRemote[rs.RemoteID] = rs.RequestCount
	}

	agg.TotalRemotes = len(s.remotes)

	return agg
}
