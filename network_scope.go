package whalewall

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/network"
)

const managedNetworksLabel = "whalewall.managed_networks"

// resolveManagedNetworks returns the concrete Docker endpoints selected by the
// managed_networks label. An absent label preserves the legacy behavior and
// selects every attached network. A present label is resolved with the same
// Compose-aware rules used by output policies.
func resolveManagedNetworks(labels map[string]string, project string, attached map[string]*network.EndpointSettings) (map[string]*network.EndpointSettings, bool, error) {
	raw, explicit := labels[managedNetworksLabel]
	if !explicit {
		return cloneNetworks(attached), false, nil
	}

	parts := strings.Split(raw, ",")
	selected := make(map[string]*network.EndpointSettings, len(parts))
	requested := make(map[string]struct{}, len(parts))
	selectedIDs := make(map[string]string, len(parts))
	for i, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			return nil, true, fmt.Errorf("%s entry #%d is empty", managedNetworksLabel, i)
		}
		if _, duplicate := requested[name]; duplicate {
			return nil, true, fmt.Errorf("%s contains duplicate network %q", managedNetworksLabel, name)
		}
		requested[name] = struct{}{}

		actualName, endpoint, ok := findNetwork(name, project, attached)
		if !ok {
			return nil, true, fmt.Errorf("managed network %q is not attached to the container", name)
		}
		if actualName == hostNetworkName {
			return nil, true, fmt.Errorf("managed network %q uses host networking, which cannot be enforced", name)
		}
		if endpoint == nil {
			return nil, true, fmt.Errorf("managed network %q has no endpoint settings", name)
		}
		if _, duplicate := selected[actualName]; duplicate {
			return nil, true, fmt.Errorf("managed network %q resolves to duplicate Docker network %q", name, actualName)
		}
		if endpoint.NetworkID != "" {
			if previous, duplicate := selectedIDs[endpoint.NetworkID]; duplicate {
				return nil, true, fmt.Errorf("managed networks %q and %q resolve to the same Docker network", previous, name)
			}
			selectedIDs[endpoint.NetworkID] = name
		}
		selected[actualName] = endpoint
	}

	return selected, true, nil
}

func cloneNetworks(attached map[string]*network.EndpointSettings) map[string]*network.EndpointSettings {
	cloned := make(map[string]*network.EndpointSettings, len(attached))
	for name, endpoint := range attached {
		cloned[name] = endpoint
	}
	return cloned
}

// collectManagedIPv4Addresses validates the selected endpoints and returns all
// usable IPv4 keys. It deliberately returns valid keys alongside an error so a
// caller can install a fail-closed floor before reporting malformed endpoint
// state.
func collectManagedIPv4Addresses(networks map[string]*network.EndpointSettings) (map[string][]byte, error) {
	names := make([]string, 0, len(networks))
	for name := range networks {
		names = append(names, name)
	}
	slices.Sort(names)

	addrs := make(map[string][]byte, len(networks))
	var validationErrs []error
	for _, name := range names {
		endpoint := networks[name]
		if endpoint == nil {
			validationErrs = append(validationErrs, fmt.Errorf("network %q has no endpoint settings", name))
			continue
		}
		if endpoint.GlobalIPv6Address.IsValid() {
			validationErrs = append(validationErrs, fmt.Errorf("network %q has IPv6 enabled; Whalewall supports IPv4 only", name))
		}
		addr := endpoint.IPAddress
		if !addr.IsValid() {
			validationErrs = append(validationErrs, fmt.Errorf("network %q has an invalid IP address", name))
			continue
		}
		if !addr.Is4() {
			validationErrs = append(validationErrs, fmt.Errorf("network %q has unsupported IP address %q; Whalewall supports IPv4 only", name, addr))
			continue
		}
		addrBytes := addr.As4()
		addrs[name] = append([]byte(nil), addrBytes[:]...)
	}

	return addrs, errors.Join(validationErrs...)
}

// resolveValidManagedNetworks is used when inspecting a peer container. Peer
// policy must be fully valid before a named-container allow can be installed;
// unlike the source policy path, it does not construct a quarantine fallback.
func resolveValidManagedNetworks(labels map[string]string, project string, attached map[string]*network.EndpointSettings) (map[string]*network.EndpointSettings, bool, error) {
	selected, explicit, err := resolveManagedNetworks(labels, project, attached)
	if err != nil {
		return nil, explicit, err
	}
	if len(selected) == 0 {
		return nil, explicit, errors.New("container has no managed network endpoints")
	}
	if explicit {
		if err := validateScopedAddressUniqueness(selected, attached); err != nil {
			return nil, explicit, err
		}
	}
	if _, err := collectManagedIPv4Addresses(selected); err != nil {
		return nil, explicit, err
	}
	return selected, explicit, nil
}

func networkEndpointIdentity(name string, endpoint *network.EndpointSettings) string {
	if endpoint != nil && endpoint.NetworkID != "" {
		return "id:" + endpoint.NetworkID
	}
	return "name:" + name
}

// validateScopedAddressUniqueness rejects a selected address that is also
// attached through an unselected network of the same container. The nftables
// dispatcher is keyed by IPv4 address, so such an overlap cannot be scoped
// without also affecting the unselected path.
func validateScopedAddressUniqueness(selected, attached map[string]*network.EndpointSettings) error {
	selectedByAddr := make(map[netip.Addr]string, len(selected))
	selectedNames := make([]string, 0, len(selected))
	for name := range selected {
		selectedNames = append(selectedNames, name)
	}
	slices.Sort(selectedNames)
	for _, name := range selectedNames {
		endpoint := selected[name]
		if endpoint != nil && endpoint.IPAddress.Is4() {
			identity := networkEndpointIdentity(name, endpoint)
			if previous, duplicate := selectedByAddr[endpoint.IPAddress]; duplicate && previous != identity {
				return fmt.Errorf("managed networks share IPv4 address %s, which cannot be scoped safely", endpoint.IPAddress)
			}
			selectedByAddr[endpoint.IPAddress] = identity
		}
	}
	for name, endpoint := range attached {
		if _, managed := selected[name]; managed || endpoint == nil || !endpoint.IPAddress.Is4() {
			continue
		}
		selectedIdentity, duplicate := selectedByAddr[endpoint.IPAddress]
		if !duplicate {
			continue
		}
		if selectedIdentity != networkEndpointIdentity(name, endpoint) {
			return fmt.Errorf("managed and unmanaged networks share IPv4 address %s, which cannot be scoped safely", endpoint.IPAddress)
		}
	}
	return nil
}
