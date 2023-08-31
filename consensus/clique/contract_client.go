package clique

import (
	"math/big"

	"github.com/holiman/uint256"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/consensus"
	"github.com/ledgerwatch/erigon/consensus/clique/ctypes"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
)

// Contract Client for calling proof-of-stake smart contract on bkc

//go:generate mockgen -destination=./mock/contract_client_mock.go -package=mock . ContractClient
type ContractClient interface {

	// // Set default signer for contract client
	// SetSigner(signer types.Signer)

	// Inject config and things in to a client
	Inject(val libcommon.Address, signFn ctypes.SignerFn, engine consensus.Engine)

	// Send slash transaction
	Slash(contract libcommon.Address, spoiledVal libcommon.Address, state *state.IntraBlockState, header *types.Header,
		txIndex int, systemTxs types.Transactions, usedGas *uint64, mining bool, currentSpan *big.Int,
	) (types.Transactions, types.Transaction, *types.Receipt, error)

	// Call for a current span number
	GetCurrentSpan(header *types.Header, ibs *state.IntraBlockState) (*big.Int, error)

	// Send distribute reward transaction
	DistributeToValidator(contract libcommon.Address, amount *uint256.Int,
		state *state.IntraBlockState, header *types.Header, txIndex int, systemTxs types.Transactions,
		usedGas *uint64, mining bool) (types.Transactions, types.Transaction, *types.Receipt, error)

	// Send commit span transaction
	CommitSpan(state *state.IntraBlockState, header *types.Header,
		txIndex int, systemTxs types.Transactions, usedGas *uint64, mining bool, validatorBytes []byte) (types.Transactions, types.Transaction, *types.Receipt, error)

	// Call is signer slashed
	IsSlashed(contract libcommon.Address, signer libcommon.Address, span *big.Int, header *types.Header, ibs *state.IntraBlockState) (bool, error)

	// Call for  current commited validators
	GetCurrentValidators(header *types.Header, ibs *state.IntraBlockState, blockNumber *big.Int) ([]*ctypes.Validator, *ctypes.SystemContracts, error)

	// Call for eligible validators
	GetEligibleValidators(header *types.Header, ibs *state.IntraBlockState) ([]*ctypes.Validator, error)
}
