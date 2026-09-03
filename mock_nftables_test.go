package whalewall

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
)

func TestMockClonePreservesNetipAddresses(t *testing.T) {
	original := struct {
		IPv4 netip.Addr
		IPv6 netip.Addr
		Zero netip.Addr
	}{
		IPv4: netip.MustParseAddr("192.0.2.10"),
		IPv6: netip.MustParseAddr("2001:db8::10"),
	}
	copied := clone(original)

	if copied.IPv4 != original.IPv4 || !copied.IPv4.Is4() {
		t.Fatalf("copied IPv4 address = %v, want %v", copied.IPv4, original.IPv4)
	}
	if copied.IPv6 != original.IPv6 || !copied.IPv6.Is6() {
		t.Fatalf("copied IPv6 address = %v, want %v", copied.IPv6, original.IPv6)
	}
	if copied.Zero != original.Zero || copied.Zero.IsValid() {
		t.Fatalf("copied zero address = %v, want invalid zero value", copied.Zero)
	}
}

func TestMockClonePreservesNftablesDatatypeMagic(t *testing.T) {
	original := &nftables.Set{
		Table:    filterTable,
		Name:     "datatype-copy",
		IsMap:    true,
		KeyType:  nftables.TypeIPAddr,
		DataType: nftables.TypeVerdict,
	}
	copied := clone(original)

	if got, want := copied.KeyType.GetNFTMagic(), original.KeyType.GetNFTMagic(); got != want {
		t.Fatalf("copied key datatype magic = %d, want %d", got, want)
	}
	if got, want := copied.DataType.GetNFTMagic(), original.DataType.GetNFTMagic(); got != want {
		t.Fatalf("copied data datatype magic = %d, want %d", got, want)
	}
	if !setSchemasEqual(copied, original) {
		t.Fatal("copied nftables set schema no longer matches its source")
	}
}
