package mullvad

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sardanioss/httpcloak/client"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
)

const (
	MullvadListURL      = "https://api.mullvad.net/www/relays/all/"
	MullvadURL          = "https://am.i.mullvad.net/json"
	MullvadListCacheTTL = 3 * time.Hour
	DefaultDNSAddr      = "194.242.2.2:853"
	DefaultDNSSNI       = "dns.mullvad.net"
)

type Status struct {
	MullvadExitIP bool   `json:"mullvad_exit_ip"`
	IP            string `json:"ip"`
	Country       string `json:"country"`
	City          string `json:"city"`
	ServerType    string `json:"mullvad_server_type"`
}

type Server struct {
	Flag      string
	Country   string
	City      string
	SOCKS5    string
	SOCKSPort int
	IPv4      string
	IPv6      string
	Speed     int
	Multihop  int
	Owned     bool
	Provider  string
	Hostname  string
}

type Provider struct {
	mu            sync.RWMutex
	mullvadList   []Server
	lastFetch     time.Time
	mullvadStatus atomic.Value
	httpClient    *client.Client
	fetchGroup    singleflight.Group
	dnsAddr       string
	dnsCache      dnsCache
}

func New() *Provider {
	return NewWithDNS("")
}

func NewWithDNS(dnsAddr string) *Provider {
	if dnsAddr == "" {
		dnsAddr = DefaultDNSAddr
	}
	return &Provider{
		httpClient: client.NewSession("chrome-latest"),
		dnsAddr:    dnsAddr,
		dnsCache:   dnsCache{entries: make(map[string]*dnsCacheEntry)},
	}
}

func (p *Provider) SOCKS5DialerFromAddr(ctx context.Context, socksAddr string, timeout time.Duration) (proxy.Dialer, error) {
	resolved, err := p.ResolveRelayAddr(ctx, socksAddr)
	if err != nil {
		return nil, err
	}
	fwd := &net.Dialer{Timeout: timeout}
	return proxy.SOCKS5("tcp", resolved, nil, fwd)
}

func (p *Provider) SOCKS5DialerFromResolved(ctx context.Context, resolvedAddr string, timeout time.Duration) (proxy.Dialer, error) {
	fwd := &net.Dialer{Timeout: timeout}
	return proxy.SOCKS5("tcp", resolvedAddr, nil, fwd)
}

func (p *Provider) ResolveRelayAddr(ctx context.Context, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if net.ParseIP(host) != nil {
		return addr, nil
	}
	ips, found := p.dnsCache.get(host)
	if !found {
		var err error
		ips, err = p.resolve(ctx, host)
		if err != nil {
			return "", fmt.Errorf("resolve relay %s: %w", host, err)
		}
		p.dnsCache.set(host, ips)
	}
	ip := preferIPv4(ips)
	if ip == nil {
		return "", fmt.Errorf("no IP for %s", host)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func preferIPv4(ips []net.IP) net.IP {
	for _, i := range ips {
		if i.To4() != nil {
			return i
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return nil
}

type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*dnsCacheEntry
}

type dnsCacheEntry struct {
	ips      []net.IP
	resolved time.Time
}

func (c *dnsCache) get(host string) ([]net.IP, bool) {
	c.mu.RLock()
	e, ok := c.entries[host]
	if !ok || time.Since(e.resolved) > 5*time.Minute {
		c.mu.RUnlock()
		return nil, false
	}
	ips := e.ips
	c.mu.RUnlock()
	out := make([]net.IP, len(ips))
	copy(out, ips)
	return out, true
}

func (c *dnsCache) set(host string, ips []net.IP) {
	cp := make([]net.IP, len(ips))
	copy(cp, ips)
	c.mu.Lock()
	c.entries[host] = &dnsCacheEntry{ips: cp, resolved: time.Now()}
	c.mu.Unlock()
}

func (p *Provider) Start(ctx context.Context, logger *slog.Logger) {
	go p.dnsRefresher(ctx, logger)
}

func (p *Provider) dnsRefresher(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.refreshDNSCache(ctx, logger)
		case <-ctx.Done():
			return
		}
	}
}

func (p *Provider) refreshDNSCache(ctx context.Context, logger *slog.Logger) {
	p.mu.RLock()
	servers := p.mullvadList
	p.mu.RUnlock()
	if len(servers) == 0 {
		return
	}
	seen := map[string]bool{}
	for _, s := range servers {
		if s.SOCKS5 == "" {
			continue
		}
		host, _, err := net.SplitHostPort(s.SOCKS5 + ":0")
		if err != nil || net.ParseIP(host) != nil {
			continue
		}
		seen[host] = true
	}
	for host := range seen {
		ips, err := p.resolve(ctx, host)
		if err != nil {
			logger.Debug("dns cache refresh failed", slog.String("host", host), slog.String("error", err.Error()))
			continue
		}
		p.dnsCache.set(host, ips)
	}
}

func (p *Provider) resolve(ctx context.Context, hostname string) ([]net.IP, error) {
	host, port, _ := net.SplitHostPort(p.dnsAddr)
	if port == "" {
		port = "53"
	}
	dnsAddr := net.JoinHostPort(host, port)
	useDoT := port == "853"

	network := "udp"
	if useDoT {
		network = "tcp"
	}

	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, network, dnsAddr)
	if err != nil {
		return nil, fmt.Errorf("dns connect: %w", err)
	}
	defer conn.Close()

	if useDoT {
		sni := host
		if net.ParseIP(host) != nil {
			sni = DefaultDNSSNI
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: sni})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("dns tls: %w", err)
		}
		conn = tlsConn
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               uint16(rand.IntN(65536)),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(hostname + "."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("dns pack: %w", err)
	}

	if useDoT {
		packed = append([]byte{byte(len(packed) >> 8), byte(len(packed))}, packed...)
	}

	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("dns write: %w", err)
	}

	var resp []byte
	if useDoT {
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, fmt.Errorf("dns read len: %w", err)
		}
		rlen := int(lenBuf[0])<<8 | int(lenBuf[1])
		resp = make([]byte, rlen)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, fmt.Errorf("dns read: %w", err)
		}
	} else {
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("dns read: %w", err)
		}
		resp = buf[:n]
	}

	var pkt dnsmessage.Message
	if err := pkt.Unpack(resp); err != nil {
		return nil, fmt.Errorf("dns unpack: %w", err)
	}

	if pkt.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("dns error: %v", pkt.Header.RCode)
	}

	var ips []net.IP
	for _, a := range pkt.Answers {
		switch b := a.Body.(type) {
		case *dnsmessage.AResource:
			ips = append(ips, net.IP(b.A[:]))
		case *dnsmessage.AAAAResource:
			ips = append(ips, net.IP(b.AAAA[:]))
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A/AAAA records for %s", hostname)
	}
	return ips, nil
}

type Filter struct {
	Countries []string `json:"country,omitempty"`
	Cities    []string `json:"city,omitempty"`
	Seed      int64    `json:"seed,omitempty"`
	Owned     *bool    `json:"owned,omitempty"`
	Providers []string `json:"provider,omitempty"`
	MinSpeed  int      `json:"speed,omitempty"`
	Multihop  bool     `json:"multihop,omitempty"`
}

type ServerProvider interface {
	FetchMullvadList(ctx context.Context) ([]Server, error)
	GetFilteredServer(ctx context.Context, filter Filter) (Server, error)
	GetFilteredServerWithHealth(ctx context.Context, filter Filter, isOnline func(string) bool) (Server, error)
	SOCKS5DialerFromAddr(ctx context.Context, socksAddr string, timeout time.Duration) (proxy.Dialer, error)
	ResolveRelayAddr(ctx context.Context, socksAddr string) (string, error)
	SOCKS5DialerFromResolved(ctx context.Context, resolvedAddr string, timeout time.Duration) (proxy.Dialer, error)
}

func stringInSlice(ss []string, s string) bool {
	for _, v := range ss {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func (p *Provider) GetFilteredServer(ctx context.Context, filter Filter) (Server, error) {
	mullvadServers, err := p.FetchMullvadList(ctx)
	if err != nil {
		return Server{}, err
	}

	if len(mullvadServers) == 0 {
		return Server{}, fmt.Errorf("no servers available")
	}

	filtered := p.filterByFilter(mullvadServers, filter)

	if len(filtered) == 0 {
		return Server{}, fmt.Errorf("no servers match filter")
	}

	if filter.Seed != 0 {
		rng := rand.New(rand.NewPCG(uint64(filter.Seed), uint64(filter.Seed)))
		index := rng.IntN(len(filtered))
		return filtered[index], nil
	}

	server := filtered[rand.IntN(len(filtered))]
	return server, nil
}

func (p *Provider) GetFilteredServerWithHealth(ctx context.Context, filter Filter, isOnline func(string) bool) (Server, error) {
	mullvadServers, err := p.FetchMullvadList(ctx)
	if err != nil {
		return Server{}, err
	}

	if len(mullvadServers) == 0 {
		return Server{}, fmt.Errorf("no servers available")
	}

	filtered := p.filterByFilter(mullvadServers, filter)

	if len(filtered) == 0 {
		return Server{}, fmt.Errorf("no servers match filter")
	}

	var healthy []Server
	for _, s := range filtered {
		if isOnline == nil || isOnline(s.Hostname) {
			healthy = append(healthy, s)
		}
	}

	if len(healthy) == 0 {
		return Server{}, fmt.Errorf("no healthy servers match filter")
	}

	if filter.Seed != 0 {
		rng := rand.New(rand.NewPCG(uint64(filter.Seed), uint64(filter.Seed)))
		index := rng.IntN(len(healthy))
		return healthy[index], nil
	}

	server := healthy[rand.IntN(len(healthy))]
	return server, nil
}

func (p *Provider) GetFilteredServers(ctx context.Context, filter Filter) ([]Server, error) {
	mullvadServers, err := p.FetchMullvadList(ctx)
	if err != nil {
		return nil, err
	}

	return p.filterByFilter(mullvadServers, filter), nil
}

func (f Filter) isEmpty() bool {
	return len(f.Countries) == 0 && len(f.Cities) == 0 && len(f.Providers) == 0 &&
		f.Seed == 0 && f.Owned == nil && f.MinSpeed == 0 && !f.Multihop
}

func (f Filter) Clone() Filter {
	return Filter{
		Countries: append([]string(nil), f.Countries...),
		Cities:    append([]string(nil), f.Cities...),
		Providers: append([]string(nil), f.Providers...),
		Seed:      f.Seed,
		Owned:     f.Owned,
		MinSpeed:  f.MinSpeed,
		Multihop:  f.Multihop,
	}
}

func (p *Provider) filterByFilter(servers []Server, filter Filter) []Server {
	if filter.isEmpty() {
		out := make([]Server, len(servers))
		copy(out, servers)
		return out
	}
	filtered := make([]Server, 0, len(servers))
	for _, s := range servers {
		if len(filter.Countries) > 0 && !stringInSlice(filter.Countries, s.Country) {
			continue
		}
		if len(filter.Cities) > 0 && !stringInSlice(filter.Cities, s.City) {
			continue
		}
		if filter.Owned != nil && s.Owned != *filter.Owned {
			continue
		}
		if len(filter.Providers) > 0 && !stringInSlice(filter.Providers, s.Provider) {
			continue
		}
		if filter.MinSpeed > 0 && s.Speed < filter.MinSpeed {
			continue
		}
		if filter.Multihop && s.Multihop == 0 {
			continue
		}
		filtered = append(filtered, s)
	}
	return filtered
}

func (p *Provider) CheckMullvadStatus(ctx context.Context) (bool, error) {
	if v := p.mullvadStatus.Load(); v != nil {
		if b, ok := v.(bool); ok {
			return b, nil
		}
	}

	resp, err := p.httpClient.Get(ctx, MullvadURL, nil)
	if err != nil {
		return false, err
	}
	defer resp.Close()

	var status Status
	if err := resp.JSON(&status); err != nil {
		return false, err
	}

	isMullvad := status.MullvadExitIP
	p.mullvadStatus.Store(isMullvad)

	return isMullvad, nil
}

func (p *Provider) FetchMullvadList(ctx context.Context) ([]Server, error) {
	p.mu.RLock()
	if !p.lastFetch.IsZero() && time.Since(p.lastFetch) < MullvadListCacheTTL && len(p.mullvadList) > 0 {
		list := p.mullvadList
		p.mu.RUnlock()
		return list, nil
	}
	p.mu.RUnlock()

	result, err, _ := p.fetchGroup.Do("mullvad-list", func() (interface{}, error) {
		resp, err := p.httpClient.Get(ctx, MullvadListURL, nil)
		if err != nil {
			return nil, err
		}
		defer resp.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		mullvadServers, err := parseMullvadRelays(body)
		if err != nil {
			return nil, err
		}

		sort.Slice(mullvadServers, func(i, j int) bool {
			return mullvadServers[i].Hostname < mullvadServers[j].Hostname
		})

		p.mu.Lock()
		p.mullvadList = mullvadServers
		p.lastFetch = time.Now()
		p.mu.Unlock()

		return mullvadServers, nil
	})
	if err != nil {
		return nil, err
	}

	return result.([]Server), nil
}

type relayJSON struct {
	Hostname         string `json:"hostname"`
	CountryCode      string `json:"country_code"`
	CountryName      string `json:"country_name"`
	CityName         string `json:"city_name"`
	Active           bool   `json:"active"`
	Owned            bool   `json:"owned"`
	Provider         string `json:"provider"`
	IPv4AddrIn       string `json:"ipv4_addr_in"`
	IPv6AddrIn       string `json:"ipv6_addr_in"`
	NetworkPortSpeed int    `json:"network_port_speed"`
	MultihopPort     int    `json:"multihop_port"`
	SocksName        string `json:"socks_name"`
	SocksPort        int    `json:"socks_port"`
}

func parseMullvadRelays(data []byte) ([]Server, error) {
	var relays []relayJSON
	if err := json.Unmarshal(data, &relays); err != nil {
		return nil, fmt.Errorf("unmarshal mullvad relays: %w", err)
	}

	servers := make([]Server, 0, len(relays))
	for _, r := range relays {
		if !r.Active {
			continue
		}
		servers = append(servers, Server{
			Flag:      r.CountryCode,
			Country:   r.CountryName,
			City:      r.CityName,
			SOCKS5:    r.SocksName,
			SOCKSPort: r.SocksPort,
			IPv4:      r.IPv4AddrIn,
			IPv6:      r.IPv6AddrIn,
			Speed:     r.NetworkPortSpeed,
			Multihop:  r.MultihopPort,
			Owned:     r.Owned,
			Provider:  r.Provider,
			Hostname:  r.Hostname,
		})
	}
	return servers, nil
}
