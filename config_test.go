package whalewall

import (
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
			name: "removed singular port syntax",
			input: `output:
  - proto: tcp
    port: 443
`,
			wantErr: "field port not found",
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
