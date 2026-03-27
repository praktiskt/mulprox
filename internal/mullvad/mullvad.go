package mullvad

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/client"
	"golang.org/x/sync/singleflight"
)

const (
	MullvadListURL      = "https://mullvad.net/en/servers"
	MullvadURL          = "https://am.i.mullvad.net/json"
	MullvadListCacheTTL = 3 * time.Hour
	FallbackMullvad     = "10.64.0.1:1080"
	preset              = "chrome-latest"
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
	STBoot    bool
	Hostname  string
}

type Provider struct {
	mu            sync.RWMutex
	mullvadList   []Server
	lastFetch     time.Time
	mullvadStatus *bool
	statusCheckMu sync.RWMutex
	httpClient    *client.Client
	fetchGroup    singleflight.Group
}

func New() *Provider {
	return &Provider{
		httpClient: client.NewSession(preset),
	}
}

func NewSession(timeout time.Duration) *client.Client {
	return client.NewSession(preset,
		client.WithTimeout(timeout),
		client.WithECHFrom("cloudflare.com"),
	)
}

func (p *Provider) Session(ctx context.Context, timeout time.Duration) (*client.Client, error) {
	mullvadServers, err := p.FetchMullvadList(ctx)
	if err != nil {
		return nil, err
	}

	server := FallbackMullvad
	if len(mullvadServers) > 0 {
		s := mullvadServers[rand.Intn(len(mullvadServers))]
		server = fmt.Sprintf("%s:%d", s.SOCKS5, s.SOCKSPort)
	}

	return client.NewSession(preset,
		client.WithTimeout(timeout),
		client.WithProxy("socks5://"+server),
	), nil
}

func (p *Provider) CheckMullvadStatus(ctx context.Context) (bool, error) {
	p.statusCheckMu.Lock()
	defer p.statusCheckMu.Unlock()

	if p.mullvadStatus != nil {
		return *p.mullvadStatus, nil
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
	p.mullvadStatus = &isMullvad

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

var relayRe = regexp.MustCompile(`hostname:"(?P<hostname>[^"]+)",country_code:"(?P<flag>[^"]+)",country_name:"(?P<country>[^"]+)",city_code:"[^"]+",city_name:"(?P<city>[^"]+)",fqdn:"[^"]+",active:(?P<active>true|false),owned:(?P<owned>true|false),provider:"(?P<provider>[^"]+)",ipv4_addr_in:"(?P<ipv4>[^"]+)",ipv6_addr_in:"(?P<ipv6>[^"]+)",network_port_speed:(?P<speed>\d+),stboot:(?P<stboot>true|false),type:"[^"]+",status_messages:\[\],pubkey:"[^"]+",multihop_port:(?P<multihop>\d+),socks_name:"(?P<socks>[^"]+)",socks_port:(?P<socksport>\d+),daita:`)

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
			STBoot:    get(m, "stboot") == "true",
			Hostname:  get(m, "hostname"),
			SOCKSPort: socksPort,
		})
	}

	return servers
}

func (p *Provider) GetServersByCountry(country string) []Server {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var result []Server
	for _, s := range p.mullvadList {
		if strings.EqualFold(s.Country, country) {
			result = append(result, s)
		}
	}
	return result
}

func (p *Provider) GetServersByCity(city string) []Server {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var result []Server
	for _, s := range p.mullvadList {
		if strings.EqualFold(s.City, city) {
			result = append(result, s)
		}
	}
	return result
}

func (p *Provider) GetOwnedServers() []Server {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var result []Server
	for _, s := range p.mullvadList {
		if s.Owned {
			result = append(result, s)
		}
	}
	return result
}

func (p *Provider) GetMultihopServers() []Server {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var result []Server
	for _, s := range p.mullvadList {
		if s.Multihop > 0 {
			result = append(result, s)
		}
	}
	return result
}
