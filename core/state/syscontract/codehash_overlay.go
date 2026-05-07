// Package syscontract holds the small, dependency-free helpers used by the
// systemContractLookup overlay in core/state.PlainState. Splitting them out
// lets unit tests run against just erigon-lib/common, without pulling in the
// broader core/state dependency graph (mdbx, consensus, etc.).
package syscontract

import (
	"sort"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
)

// PickHistoricalCodeHash mirrors the systemContractLookup overlay rule used by
// PlainState.ReadAccountData: given an ascending-by-BlockNumber list of
// CodeRecords for a system contract, return the codehash that should override
// the value decoded from history when reading state at blockNr.
//
// Returns (zeroHash, false) if blockNr precedes every record. Callers must
// treat "not found" as "leave the historical codehash unchanged" — taking
// records[-1] panics with index-out-of-range, which is the exact bug this
// helper was extracted to make testable in isolation.
//
// Boundary semantics: the predicate is strict-greater, so a record whose
// BlockNumber == blockNr is treated as already in effect. Whether that
// matches the eth_getCode "state-at-end-of-block-N" RPC convention is a
// separate concern handled in the call path, not in this helper.
func PickHistoricalCodeHash(records []libcommon.CodeRecord, blockNr uint64) (libcommon.Hash, bool) {
	p := sort.Search(len(records), func(i int) bool {
		return records[i].BlockNumber > blockNr
	})
	if p == 0 {
		return libcommon.Hash{}, false
	}
	return records[p-1].CodeHash, true
}
