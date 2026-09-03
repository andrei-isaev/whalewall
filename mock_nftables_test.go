package whalewall

import (
	"testing"

	"github.com/google/nftables"
)

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
