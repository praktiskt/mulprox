package mullvad

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sardanioss/httpcloak/client"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
)

const (
	MullvadListURL      = "https://mullvad.net/en/servers"
	MullvadURL          = "https://am.i.mullvad.net/json"
	MullvadListCacheTTL = 3 * time.Hour
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
}

func New() *Provider {
	return &Provider{
		httpClient: client.NewSession("chrome-latest"),
	}
}

func (p *Provider) SOCKS5DialerFromAddr(socksAddr string, timeout time.Duration) (proxy.Dialer, error) {
	fwd := &net.Dialer{Timeout: timeout}
	return proxy.SOCKS5("tcp", socksAddr, nil, fwd)
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
	SOCKS5DialerFromAddr(socksAddr string, timeout time.Duration) (proxy.Dialer, error)
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

func (p *Provider) GetFilteredServers(filter Filter) ([]Server, error) {
	mullvadServers, err := p.FetchMullvadList(context.Background())
	if err != nil {
		return nil, err
	}

	return p.filterByFilter(mullvadServers, filter), nil
}

func (f Filter) isEmpty() bool {
	return len(f.Countries) == 0 && len(f.Cities) == 0 && len(f.Providers) == 0 &&
		f.Seed == 0 && f.Owned == nil && f.MinSpeed == 0 && !f.Multihop
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

		mullvadServers := parseMullvadRelays(string(body))

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

var relayRe = regexp.MustCompile(`hostname:"(?P<hostname>[^"]+)",country_code:"(?P<flag>[^"]+)",country_name:"(?P<country>[^"]+)",city_code:"[^"]+",city_name:"(?P<city>[^"]+)",fqdn:"[^"]+",active:(?P<active>true|false),owned:(?P<owned>true|false),provider:"(?P<provider>[^"]+)",ipv4_addr_in:"(?P<ipv4>[^"]+)",ipv6_addr_in:"(?P<ipv6>[^"]+)",network_port_speed:(?P<speed>\d+),stboot:(?:true|false),type:"[^"]+",status_messages:\[\],pubkey:"[^"]+",multihop_port:(?P<multihop>\d+),socks_name:"(?P<socks>[^"]+)",socks_port:(?P<socksport>\d+),daita:`)

var relayNameIndex = func() map[string]int {
	names := relayRe.SubexpNames()
	m := make(map[string]int, len(names))
	for i, n := range names {
		m[n] = i
	}
	return m
}()

func parseMullvadRelays(html string) []Server {
	start := strings.Index(html, "relays:[")
	if start == -1 {
		return nil
	}

	bracketCount := 1
	end := len(html)
	for i := start + 7; i < len(html); i++ {
		if html[i] == '[' {
			bracketCount++
		} else if html[i] == ']' {
			bracketCount--
			if bracketCount == 0 {
				end = i + 1
				break
			}
		}
	}

	jsArray := html[start+7 : end]

	matches := relayRe.FindAllStringSubmatch(jsArray, -1)

	var servers []Server
	for _, m := range matches {
		if m[relayNameIndex["active"]] != "true" {
			continue
		}

		speed, _ := strconv.Atoi(m[relayNameIndex["speed"]])
		multihop, _ := strconv.Atoi(m[relayNameIndex["multihop"]])
		socksPort, _ := strconv.Atoi(m[relayNameIndex["socksport"]])

		servers = append(servers, Server{
			Flag:      m[relayNameIndex["flag"]],
			Country:   m[relayNameIndex["country"]],
			City:      m[relayNameIndex["city"]],
			SOCKS5:    m[relayNameIndex["socks"]],
			IPv4:      m[relayNameIndex["ipv4"]],
			IPv6:      m[relayNameIndex["ipv6"]],
			Speed:     speed,
			Multihop:  multihop,
			Owned:     m[relayNameIndex["owned"]] == "true",
			Provider:  m[relayNameIndex["provider"]],
			Hostname:  m[relayNameIndex["hostname"]],
			SOCKSPort: socksPort,
		})
	}

	return servers
}
