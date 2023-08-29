package ctypes

import (
	"math/big"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
)

// SignerFn is a signer callback function to request a header to be signed by a
// backing account.
type SignerFn func(signer libcommon.Address, mimeType string, message []byte) ([]byte, error)

type SystemContracts struct {
	StakeManager libcommon.Address `json:"stakeManager"`
	SlashManager libcommon.Address `json:"slashManager"`
	OfficialNode libcommon.Address `json:"officialNode"`
}

// Validator represets Volatile state for each Validator
type Validator struct {
	Address     libcommon.Address `json:"signer"`
	VotingPower uint64            `json:"power"`
}

// MinimalVal is the minimal validator representation
// Used to send validator information to bor validator contract
type MinimalVal struct {
	Signer      libcommon.Address `json:"signer"`
	VotingPower uint64            `json:"power"`
}

func (v *Validator) HeaderBytes() []byte {
	result := make([]byte, 40)
	copy(result[:20], v.Address.Bytes())
	copy(result[20:], v.PowerBytes())
	return result
}

// PowerBytes return power bytes
func (v *Validator) PowerBytes() []byte {
	powerBytes := big.NewInt(0).SetUint64(v.VotingPower).Bytes()
	result := make([]byte, 20)
	copy(result[20-len(powerBytes):], powerBytes)
	return result
}

// MinimalVal returns block number of last validator update
func (v *Validator) MinimalVal() MinimalVal {
	return MinimalVal{
		Signer:      v.Address,
		VotingPower: uint64(v.VotingPower),
	}
}
