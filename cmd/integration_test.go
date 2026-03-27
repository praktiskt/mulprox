package cmd

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
)

func TestMullvadProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p := mullvad.New()

	servers, err := p.FetchMullvadList(ctx)
	if err != nil {
		t.Fatalf("failed to fetch mullvad list: %v", err)
	}

	if len(servers) == 0 {
		t.Fatal("no mullvad servers found")
	}

	t.Logf("found %d mullvad servers", len(servers))
}

func TestMullvadSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	p := mullvad.New()

	client, err := p.Session(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(ctx, "https://am.i.mullvad.net/json", nil)
	if err != nil {
		t.Fatalf("failed to fetch: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var status struct {
		IP            string `json:"ip"`
		MullvadExitIP bool   `json:"mullvad_exit_ip"`
	}

	if err := resp.JSON(&status); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if !status.MullvadExitIP {
		t.Fatalf("expected mullvad exit IP, got %s", status.IP)
	}

	t.Logf("connected via IP: %s (mullvad: %v)", status.IP, status.MullvadExitIP)
}

func TestIPRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	p := mullvad.New()

	var IPs []string
	for i := 0; i < 5; i++ {
		client, err := p.Session(ctx, 30*time.Second)
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i+1, err)
		}

		resp, err := client.Get(ctx, "https://am.i.mullvad.net/json", nil)
		if err != nil {
			t.Fatalf("failed to fetch %d: %v", i+1, err)
		}

		var status struct {
			IP            string `json:"ip"`
			MullvadExitIP bool   `json:"mullvad_exit_ip"`
		}
		if err := resp.JSON(&status); err != nil {
			resp.Close()
			t.Fatalf("failed to parse JSON %d: %v", i+1, err)
		}
		resp.Close()
		client.Close()

		if !status.MullvadExitIP {
			t.Fatalf("expected mullvad exit IP on request %d, got %s", i+1, status.IP)
		}

		IPs = append(IPs, status.IP)
		t.Logf("request %d: IP=%s", i+1, status.IP)

		time.Sleep(500 * time.Millisecond)
	}

	uniqueIPs := make(map[string]bool)
	for _, ip := range IPs {
		uniqueIPs[ip] = true
	}

	if len(uniqueIPs) <= 1 {
		t.Logf("WARNING: IP rotation may not be working - got same IP %d times: %v", len(IPs), IPs)
	} else {
		t.Logf("IP rotation working - %d unique IPs out of 5 requests", len(uniqueIPs))
	}
}

func TestProxyThroughHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	p := mullvad.New()

	client, err := p.Session(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(ctx, "https://example.com", nil)
	if err != nil {
		t.Fatalf("failed to fetch: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := resp.Bytes()
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}

	t.Logf("fetched %d bytes from example.com", len(body))
}

func TestJsonResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	p := mullvad.New()

	client, err := p.Session(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(ctx, "https://httpbin.org/json", nil)
	if err != nil {
		t.Fatalf("failed to fetch: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var data json.RawMessage
	if err := resp.JSON(&data); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("expected non-empty JSON response")
	}

	t.Logf("received JSON: %s", string(data))
}
