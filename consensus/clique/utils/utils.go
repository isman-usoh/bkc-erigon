package utils

import (
	"errors"
	"math/big"
	"sort"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/consensus/clique/ctypes"
)

// NewValidator creates new validator
func NewValidator(address libcommon.Address, votingPower uint64) *ctypes.Validator {
	return &ctypes.Validator{
		Address:     address,
		VotingPower: votingPower,
	}
}

func SortByVotingPower(a []ctypes.Validator) []ctypes.Validator {
	sort.SliceStable(a, func(i, j int) bool {
		return a[i].VotingPower > a[j].VotingPower
	})
	return a
}

func ParseValidatorsAndPower(validatorsBytes []byte) ([]*ctypes.Validator, error) {
	if len(validatorsBytes)%40 != 0 {
		return nil, errors.New("invalid validators bytes")
	}

	result := make([]*ctypes.Validator, len(validatorsBytes)/40)
	for i := 0; i < len(validatorsBytes); i += 40 {
		address := make([]byte, 20)
		power := make([]byte, 20)

		copy(address, validatorsBytes[i:i+20])
		copy(power, validatorsBytes[i+20:i+40])

		result[i/40] = NewValidator(libcommon.BytesToAddress(address), big.NewInt(0).SetBytes(power).Uint64())
	}
	return result, nil
}

func ParseValidators(validatorsBytes []byte) ([]libcommon.Address, error) {
	if len(validatorsBytes)%40 != 0 {
		return nil, errors.New("invalid validators bytes")
	}

	result := make([]libcommon.Address, len(validatorsBytes)/40)
	for i := 0; i < len(validatorsBytes); i += 40 {
		address := make([]byte, 20)
		copy(address, validatorsBytes[i:i+20])
		result[i/40] = libcommon.BytesToAddress(address)
	}

	return result, nil
}
