package contract

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/common"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/common/hexutility"
	"github.com/ledgerwatch/erigon/accounts/abi"
	"github.com/ledgerwatch/erigon/common/u256"
	"github.com/ledgerwatch/erigon/consensus"
	"github.com/ledgerwatch/erigon/consensus/clique/ctypes"
	"github.com/ledgerwatch/erigon/consensus/misc"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/log/v3"
)

type ContractClient struct {
	stakeManagerABI abi.ABI
	slashManagerABI abi.ABI
	validatorSetABI abi.ABI
	config          *chain.Config // Consensus engine configuration parameters
	val             libcommon.Address
	signFn          ctypes.SignerFn
	engine          consensus.Engine
}

func New(config *chain.Config) (*ContractClient, error) {
	vABI, err := abi.JSON(strings.NewReader(validatorSetABI))
	if err != nil {
		return &ContractClient{}, err
	}
	sABI, err := abi.JSON(strings.NewReader(stakeManageABI))
	if err != nil {
		return &ContractClient{}, err
	}
	slABI, err := abi.JSON(strings.NewReader(slashABI))
	if err != nil {
		return &ContractClient{}, err
	}

	return &ContractClient{
		stakeManagerABI: sABI,
		slashManagerABI: slABI,
		validatorSetABI: vABI,
		config:          config,
	}, nil
}

// // This function should be called in consensus intialization (clique.New)
// func (cc *ContractClient) SetSigner(signer types.Signer) {
// 	cc.signer = signer
// }

// Initialize function, should be called after consensus engine are selected
// and account has been authorized
func (cc *ContractClient) Inject(val libcommon.Address, signFn ctypes.SignerFn, engine consensus.Engine) {
	cc.val = val
	cc.signFn = signFn
	cc.engine = engine
}

func (cc *ContractClient) Slash(contract libcommon.Address, spoiledVal libcommon.Address, state *state.IntraBlockState, header *types.Header,
	txIndex int, systemTxs types.Transactions, usedGas *uint64, mining bool, currentSpan *big.Int,
) (types.Transactions, types.Transaction, *types.Receipt, error) {
	method := "slash"
	// get packed data
	data, err := cc.slashManagerABI.Pack(method,
		spoiledVal,
		currentSpan,
	)
	if err != nil {
		log.Error("Unable to pack tx for slash", "error", err)
		return nil, nil, nil, err
	}
	// apply message
	return cc.applyTransaction(header.Coinbase, contract, u256.Num0, data, state, header, txIndex, systemTxs, usedGas, mining)
}

func (cc *ContractClient) GetCurrentSpan(header *types.Header, ibs *state.IntraBlockState) (*big.Int, error) {
	method := "currentSpanNumber"
	// get packed data
	data, err := cc.validatorSetABI.Pack(method)
	if err != nil {
		log.Error("Unable to pack tx for deposit", "error", err)
		return nil, err
	}

	msgData := hexutility.Bytes(data)
	ibsWithoutCache := state.New(ibs.StateReader)
	_, result, err := cc.systemCall(header.Coinbase, cc.config.Clique.ValidatorContract, msgData[:], ibsWithoutCache, header, u256.Num0)

	if err != nil {
		return nil, err
	}

	var ret *big.Int
	if err := cc.validatorSetABI.UnpackIntoInterface(&ret, method, result); err != nil {
		return nil, err
	}
	return ret, nil
}

func (cc *ContractClient) DistributeToValidator(contract libcommon.Address, amount *uint256.Int, state *state.IntraBlockState, header *types.Header,
	txIndex int, systemTxs types.Transactions, usedGas *uint64, mining bool,
) (types.Transactions, types.Transaction, *types.Receipt, error) {
	log.Debug("kuyyyyyyyyyyy1")

	method := "distributeReward"
	// get packed data
	data, err := cc.stakeManagerABI.Pack(method)
	if err != nil {
		log.Error("Unable to pack tx for deposit", "error", err)
		return nil, nil, nil, err
	}
	log.Debug("kuyyyyyyyyyyy2")
	// apply message
	return cc.applyTransaction(header.Coinbase, contract, amount, data, state, header, txIndex, systemTxs, usedGas, mining)
}

func (cc *ContractClient) CommitSpan(state *state.IntraBlockState, header *types.Header,
	txIndex int, systemTxs types.Transactions, usedGas *uint64, mining bool, validatorBytes []byte,
) (types.Transactions, types.Transaction, *types.Receipt, error) {
	method := "commitSpan"
	// get packed data
	data, err := cc.validatorSetABI.Pack(method,
		validatorBytes,
	)
	if err != nil {
		log.Error("Unable to pack tx for commitspan", "error", err)
		return nil, nil, nil, err
	}
	validatorContract := cc.getValidatorContract(header.Number)

	// apply message
	return cc.applyTransaction(header.Coinbase, validatorContract, u256.Num0, data, state, header, txIndex, systemTxs, usedGas, mining)
}

func (cc *ContractClient) IsSlashed(contract libcommon.Address, signer libcommon.Address, span *big.Int, header *types.Header, ibs *state.IntraBlockState) (bool, error) {
	method := "isSignerSlashed"

	// get packed data
	data, err := cc.slashManagerABI.Pack(
		method,
		signer,
		span,
	)

	if err != nil {
		log.Error("Unable to pack tx for isSignerSlashed", "error", err)
		return false, err
	}

	msgData := hexutility.Bytes(data)
	ibsWithoutCache := state.New(ibs.StateReader)
	_, result, err := cc.systemCall(header.Coinbase, contract, msgData[:], ibsWithoutCache, header, u256.Num0)
	if err != nil {
		return false, err
	}

	var out bool
	if err := cc.slashManagerABI.UnpackIntoInterface(&out, method, result); err != nil {
		return false, err
	}
	return out, nil
}

func (cc *ContractClient) GetCurrentValidators(header *types.Header, ibs *state.IntraBlockState) ([]*ctypes.Validator, *ctypes.SystemContracts, error) {
	// block
	number := header.Number

	method := "getValidators"

	// get packed data
	data, err := cc.validatorSetABI.Pack(
		method,
		number,
	)
	if err != nil {
		log.Error("Unable to pack tx for getValidators", "error", err)
		return nil, nil, err
	}
	msgData := hexutility.Bytes(data)
	ibsWithoutCache := state.New(ibs.StateReader)
	_, result, err := cc.systemCall(header.Coinbase, cc.config.Clique.ValidatorContract, msgData[:], ibsWithoutCache, header, u256.Num0)
	if err != nil {
		return nil, nil, err
	}

	var (
		ret0 = new([]libcommon.Address)
		ret1 = new([]*big.Int)
		ret2 = new([3]libcommon.Address)
	)
	out := &[]interface{}{
		ret0,
		ret1,
		ret2,
	}

	if err := cc.validatorSetABI.UnpackIntoInterface(out, method, result); err != nil {
		return nil, nil, err
	}

	valz := make([]*ctypes.Validator, len(*ret0))
	for i, a := range *ret0 {
		valz[i] = &ctypes.Validator{
			Address:     a,
			VotingPower: (*ret1)[i].Uint64(),
		}
	}
	ca := &ctypes.SystemContracts{
		StakeManager: (*ret2)[0],
		SlashManager: (*ret2)[1],
		OfficialNode: (*ret2)[2],
	}
	return valz, ca, nil
}

// GetCurrentValidators get current validators
func (cc *ContractClient) GetEligibleValidators(header *types.Header, ibs *state.IntraBlockState) ([]*ctypes.Validator, error) {
	method := "getEligibleValidators"

	// get packed data
	data, err := cc.validatorSetABI.Pack(
		method,
	)
	if err != nil {
		log.Error("Unable to pack tx for getValidator", "error", err)
		return nil, err
	}

	msgData := hexutility.Bytes(data)
	ibsWithoutCache := state.New(ibs.StateReader)
	_, result, err := cc.systemCall(header.Coinbase, cc.config.Clique.ValidatorContract, msgData[:], ibsWithoutCache, header, u256.Num0)
	if err != nil {
		return nil, err
	}

	var ret0 = new([]struct {
		Address     libcommon.Address
		VotingPower *big.Int
	})

	if err := cc.validatorSetABI.UnpackIntoInterface(ret0, method, result); err != nil {
		return nil, err
	}
	valz := make([]*ctypes.Validator, len(*ret0))
	for i, a := range *ret0 {
		valz[i] = &ctypes.Validator{
			Address:     a.Address,
			VotingPower: new(big.Int).Div(a.VotingPower, new(big.Int).SetInt64(int64(math.Pow(10, 18)))).Uint64(),
		}
	}

	return valz, nil
}

func (cc *ContractClient) getValidatorContract(number *big.Int) libcommon.Address {
	validatorContract := cc.config.Clique.ValidatorContract
	if cc.config.ChaophrayaBangkokBlock != nil && cc.config.IsChaophrayaBangkok(number.Uint64()) {
		validatorContract = cc.config.Clique.ValidatorContractV2
	}
	return validatorContract
}

func (cc *ContractClient) applyTransaction(from libcommon.Address, to libcommon.Address, value *uint256.Int, data []byte, ibs *state.IntraBlockState, header *types.Header,
	txIndex int, systemTxs types.Transactions, usedGas *uint64, mining bool,
) (types.Transactions, types.Transaction, *types.Receipt, error) {
	nonce := ibs.GetNonce(from)
	expectedTx := types.Transaction(types.NewTransaction(nonce, to, value, math.MaxUint64/2, u256.Num0, data))
	expectedHash := expectedTx.SigningHash(cc.config.ChainID)
	if from == cc.val && mining {
		// signature, err := cc.signFn(from, accounts.MimetypeClique, cc.engine)
		// if err != nil {
		// 	return nil, nil, nil, err
		// }
		// signer := types.LatestSignerForChainID(cc.config.ChainID)
		// expectedTx, err = expectedTx.WithSignature(*signer, signature)
		// if err != nil {
		// 	return nil, nil, nil, err
		// }
	} else {
		if len(systemTxs) == 0 {
			return nil, nil, nil, fmt.Errorf("supposed to get a actual transaction, but get none")
		}
		if systemTxs[0] == nil {
			return nil, nil, nil, fmt.Errorf("supposed to get a actual transaction, but get nil")
		}
		actualTx := systemTxs[0]
		actualHash := actualTx.SigningHash(cc.config.ChainID)
		if !bytes.Equal(actualHash.Bytes(), expectedHash.Bytes()) {
			return nil, nil, nil, fmt.Errorf("expected system tx (hash %v, nonce %d, to %s, value %s, gas %d, gasPrice %s, data %s), actual tx (hash %v, nonce %d, to %s, value %s, gas %d, gasPrice %s, data %s)",
				expectedHash.String(),
				expectedTx.GetNonce(),
				expectedTx.GetTo().String(),
				expectedTx.GetValue().String(),
				expectedTx.GetGas(),
				expectedTx.GetPrice().String(),
				hex.EncodeToString(expectedTx.GetData()),
				actualHash.String(),
				actualTx.GetNonce(),
				actualTx.GetTo().String(),
				actualTx.GetValue().String(),
				actualTx.GetGas(),
				actualTx.GetPrice().String(),
				hex.EncodeToString(actualTx.GetData()),
			)
		}
		expectedTx = actualTx
		// move to next
		systemTxs = systemTxs[1:]
	}
	ibs.SetTxContext(expectedTx.Hash(), libcommon.Hash{}, txIndex)
	ibs.Prepare(
		cc.config.Rules(header.Number.Uint64(), 0),
		from,
		header.Coinbase,
		&to,
		[]common.Address{},
		nil,
	)

	gasUsed, _, err := cc.systemCall(from, to, data, ibs, header, value)
	if err != nil {
		return nil, nil, nil, err
	}
	*usedGas += gasUsed
	receipt := types.NewReceipt(false, *usedGas)
	receipt.TxHash = expectedTx.Hash()
	receipt.GasUsed = gasUsed
	if err := ibs.FinalizeTx(cc.config.Rules(header.Number.Uint64(), header.Time), state.NewNoopWriter()); err != nil {
		return nil, nil, nil, err
	}
	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = ibs.GetLogs(expectedTx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = header.Hash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(txIndex)
	ibs.SetNonce(from, nonce+1)
	return systemTxs, expectedTx, receipt, nil
}

func (cc *ContractClient) systemCall(from, contract libcommon.Address, data []byte, ibs *state.IntraBlockState, header *types.Header, value *uint256.Int) (gasUsed uint64, returnData []byte, err error) {
	chainConfig := cc.config
	if chainConfig.DAOForkBlock != nil && chainConfig.DAOForkBlock.Cmp(header.Number) == 0 {
		misc.ApplyDAOHardFork(ibs)
	}
	msg := types.NewMessage(
		from,
		&contract,
		0, value,
		math.MaxUint64/2, u256.Num0,
		nil, nil,
		data, nil, false,
		true, // isFree
		nil,
	)
	vmConfig := vm.Config{NoReceipts: true}
	// Create a new context to be used in the EVM environment
	blockContext := core.NewEVMBlockContext(header, chainConfig, core.GetHashFn(header, nil), cc.engine, &from)
	evm := vm.NewEVM(blockContext, core.NewEVMTxContext(msg), ibs, chainConfig, vmConfig)
	ret, leftOverGas, err := evm.Call(
		vm.AccountRef(msg.From()),
		*msg.To(),
		msg.Data(),
		msg.Gas(),
		msg.Value(),
		false,
	)
	if err != nil {
		return 0, nil, err
	}
	return msg.Gas() - leftOverGas, ret, nil
}
