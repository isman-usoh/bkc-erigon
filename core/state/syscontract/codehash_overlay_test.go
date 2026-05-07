package syscontract

import (
	"testing"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
)

// TestPickHistoricalCodeHash pins down the current behavior of the
// systemContractLookup overlay rule. Cases use realistic Bitkub mainnet
// hardfork boundaries so that test failures map directly to the operator-
// visible boundaries surfaced by cmd/hardforkverify.
//
// Boundary semantics intentionally captured here (NOT corrected): the
// strict-greater predicate (records[i].BlockNumber > blockNr) means a
// record at block N is treated as in-effect at blockNr == N. Whether the
// off-by-one against the eth_getCode "state at end of block N" RPC
// convention is a real bug is a separate question handled in the call
// path, not in this helper.
func TestPickHistoricalCodeHash(t *testing.T) {
	h1 := libcommon.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	h2 := libcommon.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	h3 := libcommon.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333")

	// Bitkub mainnet StakeManager-style records: three checkpoints.
	threeRecord := []libcommon.CodeRecord{
		{BlockNumber: 14_115_624, CodeHash: h1}, // Chaophraya
		{BlockNumber: 25_677_934, CodeHash: h2}, // Lausanne
		{BlockNumber: 31_237_946, CodeHash: h3}, // Basel
	}
	// Bitkub mainnet NftContract / BKCValidatorSet-style records: a single
	// late checkpoint. This is the configuration that triggered the v1.2.1
	// index-out-of-range panic for any blockNr < 31_237_946.
	oneRecord := []libcommon.CodeRecord{
		{BlockNumber: 31_237_946, CodeHash: h3},
	}

	tests := []struct {
		name      string
		records   []libcommon.CodeRecord
		blockNr   uint64
		wantHash  libcommon.Hash
		wantFound bool
	}{
		// p == 0 cases — the panic-fix boundary. Must NOT touch records[-1].
		{"empty records", []libcommon.CodeRecord{}, 0, libcommon.Hash{}, false},
		{"nil records", nil, 1_000_000, libcommon.Hash{}, false},
		{"block zero, three records", threeRecord, 0, libcommon.Hash{}, false},
		{"one block before first record (three records)", threeRecord, 14_115_623, libcommon.Hash{}, false},
		{"one block before first record (one record)", oneRecord, 31_237_945, libcommon.Hash{}, false},
		{"deep pre-history with single late record", oneRecord, 25_677_933, libcommon.Hash{}, false},

		// In-effect-at-block: strict-greater predicate means N is "in effect" at blockNr=N.
		{"exactly at first record", threeRecord, 14_115_624, h1, true},
		{"one after first record", threeRecord, 14_115_625, h1, true},
		{"mid Chaophraya..Lausanne", threeRecord, 19_896_779, h1, true},

		// Off-by-one boundary against eth_getCode "end-of-block" RPC convention.
		// Current behavior returns the *next* record's hash one block early
		// (because the RPC layer effectively passes blockNr = tag+1). Pinned
		// here so that any future predicate change is visible in the diff.
		{"one block before Lausanne", threeRecord, 25_677_933, h1, true},
		{"exactly at Lausanne", threeRecord, 25_677_934, h2, true},
		{"one after Lausanne", threeRecord, 25_677_935, h2, true},
		{"mid Lausanne..Basel", threeRecord, 28_457_940, h2, true},
		{"one block before Basel", threeRecord, 31_237_945, h2, true},
		{"exactly at Basel", threeRecord, 31_237_946, h3, true},
		{"one after Basel", threeRecord, 31_237_947, h3, true},
		{"far future", threeRecord, ^uint64(0), h3, true},

		// Single-record list: post-record range.
		{"single record at exact block", oneRecord, 31_237_946, h3, true},
		{"single record one after", oneRecord, 31_237_947, h3, true},
		{"single record far future", oneRecord, ^uint64(0), h3, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotHash, gotFound := PickHistoricalCodeHash(tc.records, tc.blockNr)
			if gotFound != tc.wantFound {
				t.Fatalf("found = %v, want %v (hash=%s)", gotFound, tc.wantFound, gotHash.Hex())
			}
			if gotHash != tc.wantHash {
				t.Fatalf("hash = %s, want %s", gotHash.Hex(), tc.wantHash.Hex())
			}
		})
	}
}

// TestPickHistoricalCodeHash_NoPanicOnPreFirstRecord is the explicit
// regression guard for the v1.2.1 panic. Even with a single record whose
// BlockNumber is far above blockNr, the function must not panic.
func TestPickHistoricalCodeHash_NoPanicOnPreFirstRecord(t *testing.T) {
	records := []libcommon.CodeRecord{
		{BlockNumber: 31_237_946, CodeHash: libcommon.HexToHash("0xabc")},
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PickHistoricalCodeHash panicked on pre-first-record blockNr: %v", r)
		}
	}()
	for _, blk := range []uint64{0, 1, 14_115_623, 25_677_933, 31_237_945} {
		if _, found := PickHistoricalCodeHash(records, blk); found {
			t.Fatalf("expected found=false at blockNr=%d (pre-first-record), got true", blk)
		}
	}
}
