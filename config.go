package whalewall

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"go.uber.org/zap/zapcore"
	"go4.org/netipx"
)

type config struct {
	MappedPorts mappedPorts `yaml:"mapped_ports"`
	Output      []ruleConfig
}

type mappedPorts struct {
	Localhost localRules
	External  externalRules
}

// TODO: allow users to specify addrOrRange that is within 127.0.0.1/8?
type localRules struct {
	Allow     bool
	LogPrefix string `yaml:"log_prefix"`
	Verdict   verdict
}

type externalRules struct {
	Allow     bool
	LogPrefix string `yaml:"log_prefix"`
	IPs       []addrOrRange
	Verdict   verdict
}

type ruleConfig struct {
	LogPrefix string `yaml:"log_prefix"`
	Network   string
	IPs       []addrOrRange
	Container string
	Proto     protocol
	SrcPorts  []rulePorts `yaml:"src_ports"`
	DstPorts  []rulePorts `yaml:"dst_ports"`
	Verdict   verdict

	// Persisted routing identity for waiting rules. These fields are excluded
	// from user YAML but exported so gob records cannot later resolve a shared
	// Compose service alias to a different project/container.
	ResolvedContainerID   string `yaml:"-"`
	ResolvedContainerName string `yaml:"-"`
	SourceProject         string `yaml:"-"`
	NetworkID             string `yaml:"-"`
	IdentityVersion       uint8  `yaml:"-"`

	skip bool
}

func (r ruleConfig) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if r.LogPrefix != "" {
		enc.AddString("log_prefix", r.LogPrefix)
	}
	if r.Network != "" {
		enc.AddString("network", r.Network)
	}
	if len(r.IPs) != 0 {
		if err := enc.AddArray("ips", addrsList(r.IPs)); err != nil {
			return err
		}
	}
	if r.Container != "" {
		enc.AddString("container", r.Container)
	}
	enc.AddString("proto", r.Proto.String())
	if len(r.SrcPorts) != 0 {
		if err := enc.AddArray("src_ports", portsList(r.SrcPorts)); err != nil {
			return err
		}
	}
	if len(r.DstPorts) != 0 {
		if err := enc.AddArray("dst_ports", portsList(r.DstPorts)); err != nil {
			return err
		}
	}
	if err := enc.AddObject("verdict", r.Verdict); err != nil {
		return err
	}

	return nil
}

type verdict struct {
	Chain          string
	Queue          uint16
	InputEstQueue  uint16 `yaml:"input_est_queue"`
	OutputEstQueue uint16 `yaml:"output_est_queue"`

	drop bool
}

func (v verdict) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if v.Chain != "" {
		enc.AddString("chain", v.Chain)
	}
	if v.Queue != 0 {
		enc.AddUint16("queue", v.Queue)
	}
	if v.InputEstQueue != 0 {
		enc.AddUint16("input_est_queue", v.InputEstQueue)
	}
	if v.OutputEstQueue != 0 {
		enc.AddUint16("output_est_queue", v.OutputEstQueue)
	}
	enc.AddBool("drop", v.drop)

	return nil
}

type addrsList []addrOrRange

func (a addrsList) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, addr := range a {
		if err := enc.AppendObject(addr); err != nil {
			return err
		}
	}

	return nil
}

type addrOrRange struct {
	addr      netip.Addr
	addrRange netipx.IPRange
}

func (a addrOrRange) MarshalText() ([]byte, error) {
	if a.addr.IsValid() {
		return a.addr.MarshalText()
	}
	return a.addrRange.MarshalText()
}

func (a addrOrRange) MarshalBinary() ([]byte, error) {
	return a.MarshalText()
}

func (a *addrOrRange) UnmarshalText(text []byte) error {
	if bytes.ContainsRune(text, '/') {
		prefix := new(netip.Prefix)
		if err := prefix.UnmarshalText(text); err != nil {
			return err
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("IPv6 address %q is not supported", text)
		}
		*a = addrOrRange{addrRange: netipx.RangeOfPrefix(*prefix)}
		return nil
	} else if bytes.ContainsRune(text, '-') {
		var addrRange netipx.IPRange
		if err := addrRange.UnmarshalText(text); err != nil {
			return err
		}
		if !addrRange.From().Is4() || !addrRange.To().Is4() {
			return fmt.Errorf("IPv6 address range %q is not supported", text)
		}
		*a = addrOrRange{addrRange: addrRange}
		return nil
	}

	var addr netip.Addr
	if err := addr.UnmarshalText(text); err != nil {
		return err
	}
	if !addr.Is4() {
		return fmt.Errorf("IPv6 address %q is not supported", text)
	}
	*a = addrOrRange{addr: addr}
	return nil
}

func (a *addrOrRange) UnmarshalBinary(data []byte) error {
	return a.UnmarshalText(data)
}

func (a addrOrRange) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if a.addr.IsValid() {
		enc.AddString("addr", a.addr.String())
	} else {
		enc.AddString("addrs", a.addrRange.String())
	}
	return nil
}

func (a *addrOrRange) IsValid() bool {
	return a.addr.IsValid() || a.addrRange.IsValid()
}

func (a *addrOrRange) Addr() (netip.Addr, bool) {
	return a.addr, a.addr.IsValid()
}

func (a *addrOrRange) Range() (netip.Addr, netip.Addr, bool) {
	return a.addrRange.From(), a.addrRange.To(), a.addrRange.IsValid()
}

type protocol uint8

const (
	invalidProto protocol = iota
	tcp
	udp
)

func (p protocol) MarshalText() ([]byte, error) {
	switch p {
	case invalidProto:
		return nil, errors.New("invalid protocol")
	case tcp:
		return []byte("tcp"), nil
	case udp:
		return []byte("udp"), nil
	default:
		panic("unreachable")
	}
}

func (p *protocol) UnmarshalText(text []byte) error {
	switch {
	case bytes.Equal(text, []byte("tcp")):
		*p = tcp
	case bytes.Equal(text, []byte("udp")):
		*p = udp
	default:
		return fmt.Errorf("invalid protocol %q", string(text))
	}
	return nil
}

func (p protocol) String() string {
	switch p {
	case invalidProto:
		return "invalid protocol"
	case tcp:
		return "tcp"
	case udp:
		return "udp"
	default:
		return fmt.Sprintf("proto(%d)", p)
	}
}

type portsList []rulePorts

func (p portsList) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, port := range p {
		if err := enc.AppendObject(port); err != nil {
			return err
		}
	}

	return nil
}

type rulePorts struct {
	single   uint16
	interval portInterval
}

type portInterval struct {
	min uint16
	max uint16
}

func (p rulePorts) MarshalText() ([]byte, error) {
	if p.single != 0 {
		return []byte(strconv.Itoa(int(p.single))), nil
	}
	return []byte(fmt.Sprintf("%d-%d", p.interval.min, p.interval.max)), nil
}

func (p rulePorts) MarshalBinary() ([]byte, error) {
	return p.MarshalText()
}

func (p *rulePorts) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return errors.New("port cannot be empty")
	}

	intervalIdx := -1
	validChars := []byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-'}
	for i, char := range text {
		if !slices.Contains(validChars, char) {
			return fmt.Errorf("invalid character %q in port", char)
		}
		if char == '-' {
			if intervalIdx >= 0 {
				return errors.New("there can only be one '-' if specifying a port interval")
			}
			if i == 0 {
				return errors.New("port interval can't start with a '-'")
			}
			if i == len(text)-1 {
				return errors.New("port interval can't end with a '-'")
			}
			intervalIdx = i
		}
	}

	var parsedPorts rulePorts
	if intervalIdx >= 0 {
		intervalMin, err := strconv.ParseUint(string(text[:intervalIdx]), 10, 16)
		if err != nil {
			return fmt.Errorf("error parsing start of port interval: %w", err)
		}
		intervalMax, err := strconv.ParseUint(string(text[intervalIdx+1:]), 10, 16)
		if err != nil {
			return fmt.Errorf("error parsing end of port interval: %w", err)
		}
		if intervalMin == 0 || intervalMax == 0 {
			return errors.New("port interval values must be between 1 and 65535")
		}
		if intervalMin > intervalMax {
			return errors.New("port interval start must not be greater than its end")
		}
		parsedPorts.interval = portInterval{
			min: uint16(intervalMin),
			max: uint16(intervalMax),
		}
	} else {
		port, err := strconv.ParseUint(string(text), 10, 16)
		if err != nil {
			return fmt.Errorf("error parsing port: %w", err)
		}
		if port == 0 {
			return errors.New("port must be between 1 and 65535")
		}
		parsedPorts.single = uint16(port)
	}

	*p = parsedPorts

	return nil
}

func (p *rulePorts) UnmarshalBinary(data []byte) error {
	return p.UnmarshalText(data)
}

func (p rulePorts) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	text, _ := p.MarshalText()
	enc.AddString("ports", string(text))
	return nil
}

func validateConfig(c config) error {
	if err := validateVerdict(c.MappedPorts.Localhost.Verdict); err != nil {
		return fmt.Errorf("mapped_ports.localhost verdict: %w", err)
	}
	if err := validateVerdict(c.MappedPorts.External.Verdict); err != nil {
		return fmt.Errorf("mapped_ports.external verdict: %w", err)
	}

	for i, r := range c.Output {
		err := validateRule(r)
		if err != nil {
			return fmt.Errorf("output rule #%d: %w", i, err)
		}
	}

	return nil
}

func validateRule(r ruleConfig) error {
	if len(r.IPs) == 0 && r.Container == "" && r.Proto == invalidProto && len(r.SrcPorts) == 0 && len(r.DstPorts) == 0 {
		return errors.New("rule is empty")
	}
	if len(r.IPs) != 0 && r.Container != "" {
		return errors.New(`"ips" and "container" are mutually exclusive`)
	}

	if r.Network == "" && r.Container != "" {
		return errors.New(`"network" must be set when "container" is set`)
	}

	if len(r.SrcPorts) != 0 && r.Proto == invalidProto {
		return errors.New(`"proto" must be set when "src_ports" is set`)
	}
	if len(r.DstPorts) != 0 && r.Proto == invalidProto {
		return errors.New(`"proto" must be set when "dst_ports" is set`)
	}
	if r.Proto != invalidProto && len(r.DstPorts) == 0 {
		return errors.New(`"dst_ports" must be set when "proto" is set`)
	}

	return validateVerdict(r.Verdict)
}

func validateVerdict(v verdict) error {
	if v.Chain != "" {
		return errors.New(`"chain" verdicts are unsupported in this hardened build because they can bypass downstream Docker isolation`)
	}
	if v.Queue != 0 || v.InputEstQueue != 0 || v.OutputEstQueue != 0 {
		return errors.New(`"queue" verdicts are unsupported in this hardened build because NF_ACCEPT can bypass downstream Docker isolation`)
	}

	return nil
}
