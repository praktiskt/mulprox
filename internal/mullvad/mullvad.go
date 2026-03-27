package mullvad

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"regexp"
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

var ipPattern = regexp.MustCompile(`\b10\.124\.\d{1,3}\.\d{1,3}\b`)

type Status struct {
	MullvadExitIP bool   `json:"mullvad_exit_ip"`
	IP            string `json:"ip"`
	Country       string `json:"country"`
	City          string `json:"city"`
	ServerType    string `json:"mullvad_server_type"`
}

type Provider struct {
	mu            sync.RWMutex
	mullvadList   []string
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
		server = fmt.Sprintf("%s:1080", mullvadServers[rand.Intn(len(mullvadServers))])
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

func (p *Provider) FetchMullvadList(ctx context.Context) ([]string, error) {
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

		mullvadServers := extractMullvadServers(string(body))

		p.mu.Lock()
		p.mullvadList = mullvadServers
		p.lastFetch = time.Now()
		p.mu.Unlock()

		return mullvadServers, nil
	})
	if err != nil {
		return nil, err
	}

	return result.([]string), nil
}

func extractMullvadServers(text string) []string {
	matches := ipPattern.FindAllString(text, -1)
	seen := make(map[string]bool)
	var servers []string

	for _, ip := range matches {
		if !seen[ip] {
			seen[ip] = true
			servers = append(servers, ip)
		}
	}

	return servers
}
