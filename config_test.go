package whalewall

import (
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestAddrOrRangeUnmarshalTextIPv4(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantAddr  string
		wantFirst string
		wantLast  string
	}{
		{
			name:     "address",
			input:    "192.0.2.10",
			wantAddr: "192.0.2.10",
		},
		{
			name:      "prefix",
			input:     "192.0.2.0/24",
			wantFirst: "192.0.2.0",
			wantLast:  "192.0.2.255",
		},
		{
			name:      "range",
			input:     "192.0.2.10-192.0.2.20",
			wantFirst: "192.0.2.10",
			wantLast:  "192.0.2.20",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got addrOrRange
			if err := got.UnmarshalText([]byte(tt.input)); err != nil {
				t.Fatalf("UnmarshalText(%q) returned an error: %v", tt.input, err)
			}

			if tt.wantAddr != "" {
				addr, ok := got.Addr()
				if !ok || addr.String() != tt.wantAddr {
					t.Fatalf("UnmarshalText(%q) address = %q, %t; want %q, true", tt.input, addr, ok, tt.wantAddr)
				}
				return
			}

			first, last, ok := got.Range()
			if !ok || first.String() != tt.wantFirst || last.String() != tt.wantLast {
				t.Fatalf(
					"UnmarshalText(%q) range = %q-%q, %t; want %q-%q, true",
					tt.input,
					first,
					last,
					ok,
					tt.wantFirst,
					tt.wantLast,
				)
			}
		})
	}
}

func TestAddrOrRangeUnmarshalTextRejectsIPv6(t *testing.T) {
	for _, input := range []string{
		"2001:db8::1",
		"2001:db8::/64",
		"2001:db8::1-2001:db8::ff",
	} {
		t.Run(input, func(t *testing.T) {
			var got addrOrRange
			err := got.UnmarshalText([]byte(input))
			if err == nil || !strings.Contains(err.Error(), "IPv6") {
				t.Fatalf("UnmarshalText(%q) error = %v; want an IPv6-not-supported error", input, err)
			}
		})
	}
}

func TestRulePortsUnmarshalText(t *testing.T) {
	tests := []struct {
		input string
		want  rulePorts
	}{
		{
			input: "53",
			want:  rulePorts{single: 53},
		},
		{
			input: "80-443",
			want:  rulePorts{interval: portInterval{min: 80, max: 443}},
		},
		{
			input: "65535",
			want:  rulePorts{single: 65535},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var got rulePorts
			if err := got.UnmarshalText([]byte(tt.input)); err != nil {
				t.Fatalf("UnmarshalText(%q) returned an error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("UnmarshalText(%q) = %#v; want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func TestRulePortsUnmarshalTextRejectsInvalidPorts(t *testing.T) {
	for _, input := range []string{
		"",
		"0",
		"0-80",
		"80-0",
		"443-80",
		"-80",
		"80-",
		"80-90-100",
		"65536",
		"http",
	} {
		t.Run(input, func(t *testing.T) {
			var got rulePorts
			if err := got.UnmarshalText([]byte(input)); err == nil {
				t.Fatalf("UnmarshalText(%q) unexpectedly succeeded", input)
			}
		})
	}
}

func TestValidateConfigValidatesMappedPortVerdicts(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{
			name: "localhost",
			cfg: config{MappedPorts: mappedPorts{Localhost: localRules{Verdict: verdict{
				Chain: "custom-chain",
				Queue: 10,
			}}}},
			wantErr: "mapped_ports.localhost verdict",
		},
		{
			name: "external",
			cfg: config{MappedPorts: mappedPorts{External: externalRules{Verdict: verdict{
				Queue:         10,
				InputEstQueue: 11,
			}}}},
			wantErr: "mapped_ports.external verdict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateConfig() error = %v; want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRuleContainerDestinations(t *testing.T) {
	tests := []struct {
		name    string
		rule    ruleConfig
		wantErr string
	}{
		{
			name: "singular container",
			rule: ruleConfig{Network: "proxy", Container: "authelia"},
		},
		{
			name: "container list",
			rule: ruleConfig{Network: "proxy", Containers: []string{"authelia", "jellyfin", "homepage"}},
		},
		{
			name: "container and containers",
			rule: ruleConfig{
				Network:    "proxy",
				Container:  "authelia",
				Containers: []string{"jellyfin"},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "container and present empty ips",
			rule: ruleConfig{
				Network:   "proxy",
				Container: "authelia",
				IPs:       []addrOrRange{},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "containers and present empty ips",
			rule: ruleConfig{
				Network:    "proxy",
				Containers: []string{"authelia"},
				IPs:        []addrOrRange{},
			},
			wantErr: "mutually exclusive",
		},
		{
			name:    "empty container list",
			rule:    ruleConfig{Network: "proxy", Containers: []string{}},
			wantErr: "must contain at least one container",
		},
		{
			name:    "empty container entry",
			rule:    ruleConfig{Network: "proxy", Containers: []string{"authelia", ""}},
			wantErr: `entry #1 must not be blank`,
		},
		{
			name:    "whitespace container entry",
			rule:    ruleConfig{Network: "proxy", Containers: []string{"\t "}},
			wantErr: `entry #0 must not be blank`,
		},
		{
			name:    "duplicate container entry",
			rule:    ruleConfig{Network: "proxy", Containers: []string{"authelia", "jellyfin", "authelia"}},
			wantErr: `entry #2 duplicates entry #0 ("authelia")`,
		},
		{
			name:    "singular container requires network",
			rule:    ruleConfig{Container: "authelia"},
			wantErr: `"network" must be set`,
		},
		{
			name:    "container list requires network",
			rule:    ruleConfig{Containers: []string{"authelia"}},
			wantErr: `"network" must be set`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRule(tt.rule)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRule() returned an error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateRule() error = %v; want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeConfigExpandsContainerListsInOrder(t *testing.T) {
	input := config{
		MappedPorts: mappedPorts{
			Localhost: localRules{Allow: true, LogPrefix: "localhost"},
		},
		Output: []ruleConfig{
			{
				LogPrefix: "dns",
				Proto:     udp,
				DstPorts:  []rulePorts{{single: 53}},
			},
			{
				LogPrefix:  "backend",
				Network:    "proxy",
				Containers: []string{"authelia", "jellyfin", "homepage"},
				Proto:      tcp,
				SrcPorts:   []rulePorts{{interval: portInterval{min: 30000, max: 30100}}},
				DstPorts:   []rulePorts{{single: 443}, {interval: portInterval{min: 8000, max: 8010}}},
				Verdict:    verdict{drop: true},
			},
			{
				LogPrefix: "database",
				Network:   "application",
				Container: "postgres",
				Proto:     tcp,
				DstPorts:  []rulePorts{{single: 5432}},
			},
		},
	}

	got, err := normalizeConfig(input)
	if err != nil {
		t.Fatalf("normalizeConfig() returned an error: %v", err)
	}

	want := config{
		MappedPorts: input.MappedPorts,
		Output: []ruleConfig{
			input.Output[0],
			{
				LogPrefix:         "backend",
				Network:           "proxy",
				Container:         "authelia",
				Proto:             tcp,
				SrcPorts:          []rulePorts{{interval: portInterval{min: 30000, max: 30100}}},
				DstPorts:          []rulePorts{{single: 443}, {interval: portInterval{min: 8000, max: 8010}}},
				Verdict:           verdict{drop: true},
				fromContainerList: true,
			},
			{
				LogPrefix:         "backend",
				Network:           "proxy",
				Container:         "jellyfin",
				Proto:             tcp,
				SrcPorts:          []rulePorts{{interval: portInterval{min: 30000, max: 30100}}},
				DstPorts:          []rulePorts{{single: 443}, {interval: portInterval{min: 8000, max: 8010}}},
				Verdict:           verdict{drop: true},
				fromContainerList: true,
			},
			{
				LogPrefix:         "backend",
				Network:           "proxy",
				Container:         "homepage",
				Proto:             tcp,
				SrcPorts:          []rulePorts{{interval: portInterval{min: 30000, max: 30100}}},
				DstPorts:          []rulePorts{{single: 443}, {interval: portInterval{min: 8000, max: 8010}}},
				Verdict:           verdict{drop: true},
				fromContainerList: true,
			},
			input.Output[2],
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeConfig() = %#v; want %#v", got, want)
	}

	// Normalization must not rewrite the caller's original rule or its list.
	if !reflect.DeepEqual(input.Output[1].Containers, []string{"authelia", "jellyfin", "homepage"}) || input.Output[1].Container != "" {
		t.Fatalf("normalizeConfig() mutated its input list rule: %#v", input.Output[1])
	}
}

func TestNormalizeConfigRejectsBeforeExpansion(t *testing.T) {
	_, err := normalizeConfig(config{Output: []ruleConfig{
		{Network: "proxy", Containers: []string{"authelia", ""}},
	}})
	if err == nil || !strings.Contains(err.Error(), "output rule #0") || !strings.Contains(err.Error(), "entry #1") {
		t.Fatalf("normalizeConfig() error = %v; want indexed rule and container entry", err)
	}
}

func TestContainerListYAMLDecodeAndNormalize(t *testing.T) {
	const input = `output:
  - network: proxy
    containers:
      - authelia
      - jellyfin
      - homepage
    proto: tcp
    dst_ports:
      - 443
`
	dec := yaml.NewDecoder(strings.NewReader(input))
	dec.KnownFields(true)
	var decoded config
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("decoding container list returned an error: %v", err)
	}
	if len(decoded.Output) != 1 || !reflect.DeepEqual(decoded.Output[0].Containers, []string{"authelia", "jellyfin", "homepage"}) {
		t.Fatalf("decoded container list = %#v; want source order preserved", decoded.Output)
	}

	normalized, err := normalizeConfig(decoded)
	if err != nil {
		t.Fatalf("normalizeConfig() returned an error: %v", err)
	}
	if len(normalized.Output) != 3 {
		t.Fatalf("normalized output length = %d; want 3", len(normalized.Output))
	}
	for i, wantName := range []string{"authelia", "jellyfin", "homepage"} {
		got := normalized.Output[i]
		if got.Container != wantName || got.Containers != nil || !got.fromContainerList {
			t.Fatalf("normalized output rule #%d = %#v; want singular list-origin rule for %q", i, got, wantName)
		}
	}
}

func TestRulesConfigStrictDecoding(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name: "current syntax",
			input: `output:
  - ips:
      - 192.0.2.10
      - 198.51.100.0/24
    proto: tcp
    dst_ports:
      - 80
      - 443-444
`,
		},
		{
			name: "container list syntax",
			input: `output:
  - network: proxy
    containers:
      - authelia
      - jellyfin
      - homepage
    proto: tcp
    dst_ports:
      - 443
`,
		},
		{
			name: "container list must be a list",
			input: `output:
  - network: proxy
    containers: authelia
`,
			wantErr: "cannot unmarshal",
		},
		{
			name: "empty singular container is rejected",
			input: `output:
  - network: proxy
    container: ""
    proto: tcp
    dst_ports: [443]
`,
			wantErr: `"container" must not be empty`,
		},
		{
			name: "null container list is rejected",
			input: `output:
  - network: proxy
    containers: null
    proto: tcp
    dst_ports: [443]
`,
			wantErr: `"containers" must contain at least one container`,
		},
		{
			name: "empty container list is rejected",
			input: `output:
  - network: proxy
    containers: []
    proto: tcp
    dst_ports: [443]
`,
			wantErr: `"containers" must contain at least one container`,
		},
		{
			name: "null singular container is rejected",
			input: `output:
  - network: proxy
    container: null
    proto: tcp
    dst_ports: [443]
`,
			wantErr: `"container" must not be empty`,
		},
		{
			name: "selector presence is mutually exclusive",
			input: `output:
  - network: proxy
    ips: []
    containers:
      - authelia
    proto: tcp
    dst_ports: [443]
`,
			wantErr: "mutually exclusive",
		},
		{
			name: "empty IP selector is rejected",
			input: `output:
  - network: proxy
    ips: []
    proto: tcp
    dst_ports: [443]
`,
			wantErr: `"ips" must contain at least one address`,
		},
		{
			name: "null IP selector is rejected",
			input: `output:
  - network: proxy
    ips: null
    proto: tcp
    dst_ports: [443]
`,
			wantErr: `"ips" must contain at least one address`,
		},
		{
			name: "null selector remains mutually exclusive",
			input: `output:
  - network: proxy
    container: null
    containers: [authelia]
    proto: tcp
    dst_ports: [443]
`,
			wantErr: "mutually exclusive",
		},
		{
			name: "cross-rule list alias remains supported",
			input: `output:
  - network: proxy
    containers: &backends [authelia, jellyfin]
  - network: proxy
    containers: *backends
`,
		},
		{
			name: "unknown output field remains rejected",
			input: `output:
  - network: proxy
    container_selector: authelia
`,
			wantErr: "field container_selector not found",
		},
		{
			name: "removed singular port syntax",
			input: `output:
  - proto: tcp
    port: 443
`,
			wantErr: "field port not found",
		},
		{
			name: "unknown verdict field remains rejected",
			input: `output:
  - proto: tcp
    dst_ports: [443]
    verdict:
      accept: true
`,
			wantErr: "field accept not found",
		},
		{
			name: "quoted merge-like verdict key remains rejected",
			input: `output:
  - proto: tcp
    dst_ports: [443]
    verdict:
      "<<": {queue: 1}
`,
			wantErr: "field << not found",
		},
		{
			name: "quoted merge-like rule key remains rejected",
			input: `output:
  - proto: tcp
    dst_ports: [443]
    "<<": {network: proxy}
`,
			wantErr: "field << not found",
		},
		{
			name: "output must be a list",
			input: `output:
  proto: tcp
  dst_ports:
    - 443
`,
			wantErr: "cannot unmarshal",
		},
		{
			name: "IPv6 is unsupported",
			input: `output:
  - ips:
      - 2001:db8::1
    proto: tcp
    dst_ports:
      - 443
`,
			wantErr: "IPv6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := yaml.NewDecoder(strings.NewReader(tt.input))
			dec.KnownFields(true)

			var cfg config
			err := dec.Decode(&cfg)
			if err == nil {
				err = validateConfig(cfg)
			}

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("valid configuration returned an error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("configuration error = %v; want error containing %q", err, tt.wantErr)
			}
		})
	}
}
