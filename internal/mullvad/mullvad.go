package mullvad

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/client"
	"golang.org/x/sync/singleflight"
)

const (
	MullvadListURL      = "https://raw.githubusercontent.com/maximko/mullvad-socks-list/list/mullvad-socks-list.txt"
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
	Flag     string
	Country  string
	City     string
	SOCKS5   string
	IPv4     string
	IPv6     string
	Speed    int
	Multihop int
	Owned    bool
	Provider string
	STBoot   bool
	Hostname string
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
		server = fmt.Sprintf("%s:1080", mullvadServers[rand.Intn(len(mullvadServers))].SOCKS5)
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

		mullvadServers := parseMullvadList(string(body))

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

func parseMullvadList(text string) []Server {
	lines := strings.Split(text, "\n")
	var servers []Server

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Date:") || strings.HasPrefix(line, "Total active") {
			continue
		}

		if len(line) < 80 || strings.HasPrefix(line, " flag") {
			continue
		}

		server, ok := parseServerLine(line)
		if ok {
			servers = append(servers, server)
		}
	}

	return servers
}

var multiWordCountries = map[string]string{
	"New":   "New Zealand",
	"South": "South Africa",
	"Czech": "Czech Republic",
	"Hong":  "Hong Kong",
}

func parseServerLine(line string) (Server, bool) {
	fields := strings.Fields(line)

	if len(fields) < 12 {
		return Server{}, false
	}

	countryIdx := 1
	if nextField, ok := multiWordCountries[fields[1]]; ok {
		if fields[2] == strings.Fields(nextField)[1] {
			countryIdx = 2
		}
	}

	s := Server{
		Flag:    fields[0],
		Country: strings.Join(fields[1:countryIdx+1], " "),
	}

	cityStart := countryIdx + 1

	s.SOCKS5 = fields[len(fields)-9]
	s.IPv4 = fields[len(fields)-8]
	s.IPv6 = fields[len(fields)-7]
	s.Provider = fields[len(fields)-3]
	s.Hostname = fields[len(fields)-1]

	if !strings.Contains(s.SOCKS5, ".") {
		return Server{}, false
	}

	s.City = strings.Join(fields[cityStart:len(fields)-9], " ")

	fmt.Sscanf(fields[len(fields)-6], "%d", &s.Speed)
	fmt.Sscanf(fields[len(fields)-5], "%d", &s.Multihop)

	s.Owned = fields[len(fields)-3] == "✔"
	s.STBoot = fields[len(fields)-2] == "✔"

	return s, true
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
