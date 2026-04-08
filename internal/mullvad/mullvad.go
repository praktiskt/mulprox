package mullvad

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"regexp"
	"sort"
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
	FallbackMullvad     = "10.64.0.1:1080"
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
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	return &timeoutDialer{dialer, timeout}, nil
}

type Filter struct {
	Countries []string
	Cities    []string
	Owned     *bool
	Providers []string
	MinSpeed  int
	Multihop  bool
	Seed      int64
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
		rng := rand.New(rand.NewSource(filter.Seed))
		index := rng.Intn(len(filtered))
		return filtered[index], nil
	}

	server := filtered[rand.Intn(len(filtered))]
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
		rng := rand.New(rand.NewSource(filter.Seed))
		index := rng.Intn(len(healthy))
		return healthy[index], nil
	}

	server := healthy[rand.Intn(len(healthy))]
	return server, nil
}

func (p *Provider) GetFilteredServers(filter Filter) ([]Server, error) {
	mullvadServers, err := p.FetchMullvadList(context.Background())
	if err != nil {
		return nil, err
	}

	return p.filterByFilter(mullvadServers, filter), nil
}

func (p *Provider) filterByFilter(servers []Server, filter Filter) []Server {
	var filtered []Server
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

type timeoutDialer struct {
	dialer  proxy.Dialer
	timeout time.Duration
}

func (d *timeoutDialer) Dial(network, address string) (net.Conn, error) {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		conn, err := d.dialer.Dial(network, address)
		ch <- result{conn, err}
	}()

	select {
	case r := <-ch:
		return r.conn, r.err
	case <-timeoutCtx.Done():
		return nil, timeoutCtx.Err()
	}
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
	names := relayRe.SubexpNames()

	get := func(m []string, name string) string {
		for i, n := range names {
			if n == name {
				return m[i]
			}
		}
		return ""
	}

	var servers []Server
	for _, m := range matches {
		if get(m, "active") != "true" {
			continue
		}

		speed := 0
		fmt.Sscanf(get(m, "speed"), "%d", &speed)
		multihop := 0
		fmt.Sscanf(get(m, "multihop"), "%d", &multihop)
		socksPort := 0
		fmt.Sscanf(get(m, "socksport"), "%d", &socksPort)

		servers = append(servers, Server{
			Flag:      get(m, "flag"),
			Country:   get(m, "country"),
			City:      get(m, "city"),
			SOCKS5:    get(m, "socks"),
			IPv4:      get(m, "ipv4"),
			IPv6:      get(m, "ipv6"),
			Speed:     speed,
			Multihop:  multihop,
			Owned:     get(m, "owned") == "true",
			Provider:  get(m, "provider"),
			Hostname:  get(m, "hostname"),
			SOCKSPort: socksPort,
		})
	}

	return servers
}
