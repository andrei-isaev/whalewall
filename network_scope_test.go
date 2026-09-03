package whalewall

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/network"
)

func TestResolveManagedNetworks(t *testing.T) {
	proxy := &network.EndpointSettings{
		NetworkID: "proxy-id",
		IPAddress: netip.MustParseAddr("172.30.0.2"),
	}
	monitoring := &network.EndpointSettings{
		NetworkID: "monitoring-id",
		IPAddress: netip.MustParseAddr("172.31.0.2"),
	}
	attached := map[string]*network.EndpointSettings{
		"demo_proxy":      proxy,
		"demo_monitoring": monitoring,
	}

	tests := []struct {
		name         string
		labels       map[string]string
		wantExplicit bool
		wantNames    []string
	}{
		{
			name:      "absent selects every attached network",
			labels:    map[string]string{},
			wantNames: []string{"demo_monitoring", "demo_proxy"},
		},
		{
			name:         "compose name",
			labels:       map[string]string{managedNetworksLabel: "proxy"},
			wantExplicit: true,
			wantNames:    []string{"demo_proxy"},
		},
		{
			name:         "multiple names with whitespace",
			labels:       map[string]string{managedNetworksLabel: " proxy, monitoring "},
			wantExplicit: true,
			wantNames:    []string{"demo_monitoring", "demo_proxy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, explicit, err := resolveManagedNetworks(tt.labels, "demo", attached)
			if err != nil {
				t.Fatalf("resolveManagedNetworks() returned an error: %v", err)
			}
			if explicit != tt.wantExplicit {
				t.Fatalf("explicit = %t; want %t", explicit, tt.wantExplicit)
			}
			for _, name := range tt.wantNames {
				if got[name] == nil {
					t.Errorf("resolved scope does not contain %q: %#v", name, got)
				}
			}
			if len(got) != len(tt.wantNames) {
				t.Fatalf("resolved scope length = %d; want %d", len(got), len(tt.wantNames))
			}
		})
	}
}

func TestResolveManagedNetworksRejectsInvalidScope(t *testing.T) {
	attached := map[string]*network.EndpointSettings{
		"demo_proxy": {
			NetworkID: "proxy-id",
			IPAddress: netip.MustParseAddr("172.30.0.2"),
		},
	}
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{name: "empty", value: "", wantErr: "entry #0 is empty"},
		{name: "leading comma", value: ",proxy", wantErr: "entry #0 is empty"},
		{name: "trailing comma", value: "proxy,", wantErr: "entry #1 is empty"},
		{name: "missing", value: "proxy,missing", wantErr: `managed network "missing" is not attached`},
		{name: "duplicate request", value: "proxy,proxy", wantErr: "duplicate network"},
		{name: "duplicate resolution", value: "proxy,demo_proxy", wantErr: "duplicate Docker network"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, explicit, err := resolveManagedNetworks(
				map[string]string{managedNetworksLabel: tt.value},
				"demo",
				attached,
			)
			if !explicit {
				t.Fatal("present label was not reported as explicit")
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("resolveManagedNetworks() error = %v; want %q", err, tt.wantErr)
			}
		})
	}
}

func TestResolveValidManagedNetworksIgnoresUnselectedUnsupportedEndpoint(t *testing.T) {
	selected, explicit, err := resolveValidManagedNetworks(
		map[string]string{managedNetworksLabel: "proxy"},
		"demo",
		map[string]*network.EndpointSettings{
			"demo_proxy": {
				NetworkID: "proxy-id",
				IPAddress: netip.MustParseAddr("172.30.0.2"),
			},
			"demo_ipv6": {
				NetworkID:         "ipv6-id",
				IPAddress:         netip.MustParseAddr("172.31.0.2"),
				GlobalIPv6Address: netip.MustParseAddr("2001:db8::2"),
			},
		},
	)
	if err != nil {
		t.Fatalf("unselected IPv6 endpoint invalidated scope: %v", err)
	}
	if !explicit || len(selected) != 1 || selected["demo_proxy"] == nil {
		t.Fatalf("resolved scope = %#v, explicit=%t; want only demo_proxy", selected, explicit)
	}
}

func TestValidateScopedAddressUniqueness(t *testing.T) {
	proxy := &network.EndpointSettings{
		NetworkID: "proxy-id",
		IPAddress: netip.MustParseAddr("172.30.0.2"),
	}
	monitoring := &network.EndpointSettings{
		NetworkID: "monitoring-id",
		IPAddress: proxy.IPAddress,
	}
	err := validateScopedAddressUniqueness(
		map[string]*network.EndpointSettings{"proxy": proxy},
		map[string]*network.EndpointSettings{"proxy": proxy, "monitoring": monitoring},
	)
	if err == nil || !strings.Contains(err.Error(), "cannot be scoped safely") {
		t.Fatalf("validateScopedAddressUniqueness() error = %v; want overlap rejection", err)
	}
}

func TestCollectManagedIPv4AddressesReturnsUsableKeysWithErrors(t *testing.T) {
	addrs, err := collectManagedIPv4Addresses(map[string]*network.EndpointSettings{
		"proxy": {
			IPAddress: netip.MustParseAddr("172.30.0.2"),
		},
		"broken": nil,
	})
	if err == nil || !strings.Contains(err.Error(), `network "broken" has no endpoint settings`) {
		t.Fatalf("collectManagedIPv4Addresses() error = %v; want nil-endpoint error", err)
	}
	if got := addrs["proxy"]; netip.AddrFrom4([4]byte(got)) != netip.MustParseAddr("172.30.0.2") {
		t.Fatalf("usable address = %v; want 172.30.0.2", got)
	}
}
