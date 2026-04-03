package stats

import (
	"sync"
	"sync/atomic"
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
	RemoteID     string        `json:"remote_id"`
	Hostname     string        `json:"hostname"`
	Country      string        `json:"country"`
	City         string        `json:"city"`
	EgressIP     string        `json:"egress_ip"`
	RequestCount atomic.Uint64 `json:"request_count"`
	BytesSent    atomic.Uint64 `json:"bytes_sent"`
	BytesRecv    atomic.Uint64 `json:"bytes_recv"`
	ErrorCount   atomic.Uint64 `json:"error_count"`
	LatencySum   atomic.Int64  `json:"latency_sum"`
	LatencyCount atomic.Uint64 `json:"latency_count"`
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
	Window            []WindowStat      `json:"window"`
}

type WindowStat struct {
	Requests      uint64 `json:"requests"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesRecv     uint64 `json:"bytes_recv"`
	Errors        uint64 `json:"errors"`
	ActiveRemotes int    `json:"active_remotes"`
	TotalRemotes  int    `json:"total_remotes"`
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
	remotes sync.Map
}

func NewRemoteStore() *RemoteStore {
	return &RemoteStore{}
}

func (s *RemoteStore) GetOrCreate(remoteID string) *RemoteStats {
	if stats, ok := s.remotes.Load(remoteID); ok {
		return stats.(*RemoteStats)
	}

	stats := &RemoteStats{
		RemoteID:  remoteID,
		CreatedAt: time.Now(),
	}
	actual, loaded := s.remotes.LoadOrStore(remoteID, stats)
	if loaded {
		return actual.(*RemoteStats)
	}
	return stats
}

func (s *RemoteStore) GetAll() []*RemoteStats {
	result := make([]*RemoteStats, 0, 64)
	s.remotes.Range(func(key, value interface{}) bool {
		result = append(result, value.(*RemoteStats))
		return true
	})
	return result
}

func (s *RemoteStore) GetAggregated() AggregatedStats {
	var agg AggregatedStats
	agg.RequestsPerRemote = make(map[string]uint64)

	s.remotes.Range(func(key, value interface{}) bool {
		rs := value.(*RemoteStats)
		reqCount := rs.RequestCount.Load()
		agg.TotalRequests += reqCount
		agg.TotalBytesSent += rs.BytesSent.Load()
		agg.TotalBytesRecv += rs.BytesRecv.Load()
		agg.TotalErrors += rs.ErrorCount.Load()
		if rs.EgressIP != "" && rs.Health.Online {
			agg.ActiveRemotes++
		}
		if rs.Health.Online {
			agg.OnlineRemotes++
		}
		agg.RequestsPerRemote[rs.RemoteID] = reqCount
		return true
	})

	s.remotes.Range(func(key, value interface{}) bool {
		agg.TotalRemotes++
		return true
	})

	return agg
}

func (s *RemoteStats) IsOnline() bool {
	return s.Health.Online
}
