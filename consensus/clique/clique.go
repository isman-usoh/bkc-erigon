// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package clique implements the proof-of-authority consensus engine.
package clique

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/goccy/go-json"
	lru "github.com/hashicorp/golang-lru/arc/v2"
	"github.com/ledgerwatch/erigon/consensus/clique/ctypes"
	"github.com/ledgerwatch/erigon/turbo/services"
	"github.com/ledgerwatch/log/v3"
	"golang.org/x/exp/slices"

	"github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"

	"github.com/ledgerwatch/erigon/common"
	"github.com/ledgerwatch/erigon/common/dbutils"
	"github.com/ledgerwatch/erigon/common/debug"
	"github.com/ledgerwatch/erigon/common/hexutil"
	"github.com/ledgerwatch/erigon/common/u256"
	"github.com/ledgerwatch/erigon/consensus"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/types/accounts"
	"github.com/ledgerwatch/erigon/crypto"
	"github.com/ledgerwatch/erigon/crypto/cryptopool"
	"github.com/ledgerwatch/erigon/params"
	"github.com/ledgerwatch/erigon/rlp"
	"github.com/ledgerwatch/erigon/rpc"
)

const (
	checkpointInterval   = 1024                   // Number of blocks after which to save the vote snapshot to the database
	epochLength          = uint64(30000)          // Default number of blocks after which to checkpoint and reset the pending votes
	ExtraVanity          = 32                     // Fixed number of extra-data prefix bytes reserved for signer vanity
	ExtraSeal            = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for signer seal
	warmupCacheSnapshots = 20

	validatorBytesLength = 40                     // Validator has 20 bytes for an address and 20 for a power
	contractBytesLength  = 60                     // Bytes length of 3 PoS contracts (20 each)
	totalPosContracts    = 3                      // Number of PoS contracts checked when retrieving from the validator set contract
	wiggleTime           = 500 * time.Millisecond // Random delay (per signer) to allow concurrent signers
)

// Clique proof-of-authority protocol constants.
var (
	NonceAuthVote = hexutil.MustDecode("0xffffffffffffffff") // Magic nonce number to vote on adding a new signer
	nonceDropVote = hexutil.MustDecode("0x0000000000000000") // Magic nonce number to vote on removing a signer.

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	DiffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// errInvalidVote is returned if a nonce value is something else that the two
	// allowed constants of 0x00..0 or 0xff..f.
	errInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")

	// errInvalidCheckpointVote is returned if a checkpoint/epoch transition block
	// has a vote nonce set to non-zeroes.
	errInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errExtraSigners is returned if non-checkpoint block contain signer data in
	// their extra-data fields.
	errExtraSigners = errors.New("non-checkpoint block contains extra signer list")

	// errInvalidCheckpointSigners is returned if a checkpoint block contains an
	// invalid list of signers (i.e. non divisible by 20 bytes).
	errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// errMismatchingCheckpointSigners is returned if a checkpoint block contains a
	// list of signers different than the one the local node calculated.
	errMismatchingCheckpointSigners = errors.New("mismatching signer list on checkpoint block")

	// errMismatchingSpanValidators is returned if a sprint block contains a
	// list of validators different than the one the local node calculated.
	errMismatchingSpanValidators = errors.New("mismatching validator list on span block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// ErrUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	ErrUnauthorizedSigner = errors.New("unauthorized signer")

	// ErrRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	ErrRecentlySigned = errors.New("recently signed")

	// Fail to get the given snapshot
	errGetSnapshotFailed = errors.New("fail to get the snapshot")

	// Invalid span
	errInvalidSpan = errors.New("invalid span")
)

// SignerFn is a signer callback function to request a header to be signed by a
// backing account.
type SignerFn func(signer libcommon.Address, mimeType string, message []byte) ([]byte, error)

func (c *Clique) isToSystemContract(to libcommon.Address, snap *Snapshot) bool {
	// Map system contracts
	systemContracts := map[libcommon.Address]bool{
		c.config.ValidatorContractV2:      true,
		c.config.ValidatorContract:        true,
		snap.SystemContracts.StakeManager: true,
		snap.SystemContracts.SlashManager: true,
	}
	return systemContracts[to]
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigcache *lru.ARCCache[libcommon.Hash, libcommon.Address]) (libcommon.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()

	// hitrate while straight-forward sync is from 0.5 to 0.65
	if address, known := sigcache.Peek(hash); known {
		return address, nil
	}

	// Retrieve the signature from the header extra-data
	if len(header.Extra) < ExtraSeal {
		return libcommon.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-ExtraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header).Bytes(), signature)
	if err != nil {
		return libcommon.Address{}, err
	}

	var signer libcommon.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

// Clique is the proof-of-authority consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type Clique struct {
	ChainConfig    *chain.Config
	config         *chain.CliqueConfig             // Consensus engine configuration parameters
	snapshotConfig *params.ConsensusSnapshotConfig // Consensus engine configuration parameters
	DB             kv.RwDB                         // Database to store and retrieve snapshot checkpoints

	signatures *lru.ARCCache[libcommon.Hash, libcommon.Address] // Signatures of recent blocks to speed up mining
	recents    *lru.ARCCache[libcommon.Hash, *Snapshot]         // Snapshots for recent block to speed up reorgs

	proposals map[libcommon.Address]bool // Current list of proposals we are pushing

	signer *types.Signer

	val    libcommon.Address // Ethereum address of the signing key
	signFn ctypes.SignerFn   // Signer function to authorize hashes with
	lock   sync.RWMutex      // Protects the signer and proposals fields

	// The fields below are for testing only
	FakeDiff bool // Skip difficulty verifications

	exitCh chan struct{}
	logger log.Logger

	contractClient ContractClient
}

// New creates a Clique proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
func New(cfg *chain.Config, snapshotConfig *params.ConsensusSnapshotConfig, cliqueDB kv.RwDB, logger log.Logger, contractClient ContractClient,
) *Clique {
	config := cfg.Clique

	// Set any missing consensus parameters to their defaults
	conf := *config
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}
	// Allocate the snapshot caches and create the engine
	recents, _ := lru.NewARC[libcommon.Hash, *Snapshot](snapshotConfig.InmemorySnapshots)
	signatures, _ := lru.NewARC[libcommon.Hash, libcommon.Address](snapshotConfig.InmemorySignatures)

	exitCh := make(chan struct{})

	c := &Clique{
		ChainConfig:    cfg,
		config:         &conf,
		snapshotConfig: snapshotConfig,
		DB:             cliqueDB,
		recents:        recents,
		signatures:     signatures,
		contractClient: contractClient,
		proposals:      make(map[libcommon.Address]bool),
		exitCh:         exitCh,
		logger:         logger,
		signer:         types.LatestSigner(cfg),
	}

	// warm the cache
	snapNum, err := lastSnapshot(cliqueDB, logger)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			logger.Error("on Clique init while getting latest snapshot", "err", err)
		}
	} else {
		snaps, err := c.snapshots(snapNum, warmupCacheSnapshots)
		if err != nil {
			logger.Error("on Clique init", "err", err)
		}

		for _, sn := range snaps {
			c.recentsAdd(sn.Number, sn.Hash, sn)
		}
	}

	return c
}

func (c *Clique) IsSystemTransaction(tx types.Transaction, header *types.Header, chain consensus.ChainHeaderReader) (bool, error) {
	// deploy a contract
	if tx.GetTo() == nil {
		return false, nil
	}
	sender, err := tx.Sender(*c.signer)
	if err != nil {
		return false, errors.New("UnAuthorized transaction")
	}

	snap, err := c.Snapshot(chain, header.Number.Uint64()-1, header.ParentHash, nil)
	if err != nil {
		return false, errGetSnapshotFailed
	}

	if sender == header.Coinbase && c.isToSystemContract(*tx.GetTo(), snap) && tx.GetPrice().IsZero() {
		return true, nil
	}
	return false, nil
}

// Type returns underlying consensus engine
func (c *Clique) Type() chain.ConsensusName {
	return chain.CliqueConsensus
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
// This is thread-safe (only access the header, as well as signatures, which
// are lru.ARCCache, which is thread-safe)
func (c *Clique) Author(header *types.Header) (libcommon.Address, error) {
	return ecrecover(header, c.signatures)
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (c *Clique) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, _ bool) error {
	return c.verifyHeader(chain, header, nil)
}

type VerifyHeaderResponse struct {
	Results chan error
	Cancel  func()
}

func (c *Clique) recentsAdd(num uint64, hash libcommon.Hash, s *Snapshot) {
	c.recents.Add(hash, s.copy())
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *Clique) VerifyUncles(chain consensus.ChainReader, header *types.Header, uncles []*types.Header) error {
	if len(uncles) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (c *Clique) VerifySeal(chain consensus.ChainHeaderReader, header *types.Header) error {

	snap, err := c.Snapshot(chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return err
	}
	return c.verifySeal(chain, header, snap)
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (c *Clique) Prepare(chain consensus.ChainHeaderReader, header *types.Header, state *state.IntraBlockState) error {

	// If the block isn't a checkpoint, cast a random vote (good enough for now)
	number := header.Number.Uint64()
	if !chain.Config().IsErawan(number) {
		header.Coinbase = libcommon.Address{}
	}
	if chain.Config().IsChaophraya(number) {
		header.Coinbase = c.val
	}
	header.Nonce = types.BlockNonce{}

	// Assemble the voting snapshot to check which votes make sense
	snap, err := c.Snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	c.lock.RLock()
	if !isOnEpochStart(c.ChainConfig, header.Number) {
		// Gather all the proposals that make sense voting on
		addresses := make([]libcommon.Address, 0, len(c.proposals))
		for address, authorize := range c.proposals {
			if snap.validVote(address, authorize) {
				addresses = append(addresses, address)
			}
		}
		// If there's pending proposals, cast a vote on them
		if len(addresses) > 0 {
			addr := addresses[rand.Intn(len(addresses))]
			if chain.Config().IsErawan(header.Number.Uint64()) {
				header.MixDigest = addr.Hash()
			} else {
				header.Coinbase = addr
			}
			if c.proposals[addr] {
				copy(header.Nonce[:], NonceAuthVote)
			} else {
				copy(header.Nonce[:], nonceDropVote)
			}
		}

	}
	// Copy signer protected by mutex to avoid race condition
	val := c.val
	c.lock.RUnlock()

	// Set the correct difficulty
	header.Difficulty = calcDifficulty(snap, val)

	// Ensure the extra data has all its components
	if len(header.Extra) < ExtraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, ExtraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:ExtraVanity]

	if isOnEpochStart(c.ChainConfig, header.Number) {
		if !chain.Config().IsChaophraya(header.Number.Uint64()) {
			for _, signer := range snap.GetSigners() {
				header.Extra = append(header.Extra, signer[:]...)
			}
		}
	}
	if number > 0 && isNextBlockPoS(c.ChainConfig, header.Number) {
		if needToUpdateValidatorList(c.ChainConfig, header.Number) {
			newValidators, systemContracts, err := c.contractClient.GetCurrentValidators(header, state, new(big.Int).SetUint64(number+1))
			if err != nil {
				log.Error("GetCurrentValidators", "err", err.Error())
				return errors.New("unknown validators")
			}
			for _, validator := range newValidators {
				header.Extra = append(header.Extra, validator.HeaderBytes()...)
			}
			// // Add StakeManager bytes to header.Extra
			header.Extra = append(header.Extra, systemContracts.StakeManager.Bytes()...)
			// // Add SlashManager bytes to header.Extra
			header.Extra = append(header.Extra, systemContracts.SlashManager.Bytes()...)
			// // Add OfficialNode bytes to header.Extra
			header.Extra = append(header.Extra, systemContracts.OfficialNode.Bytes()...)
		}
	}

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	header.Extra = append(header.Extra, make([]byte, ExtraSeal)...)

	header.Time = parent.Time + c.config.Period

	now := uint64(time.Now().Unix())
	if header.Time < now {
		header.Time = now
	}

	return nil
}

func (c *Clique) Initialize(config *chain.Config, chain consensus.ChainHeaderReader, header *types.Header,
	state *state.IntraBlockState, txs []types.Transaction, uncles []*types.Header, syscall consensus.SysCallCustom) {
}

func (c *Clique) CalculateRewards(config *chain.Config, header *types.Header, uncles []*types.Header, syscall consensus.SystemCall,
) ([]consensus.Reward, error) {
	return []consensus.Reward{}, nil
}

func ParseAddressBytes(b []byte) ([]*libcommon.Address, error) {
	if len(b)%20 != 0 {
		return nil, errors.New("invalid address bytes")
	}
	result := make([]*libcommon.Address, len(b)/20)
	for i := 0; i < len(b); i += 20 {
		address := make([]byte, 20)
		copy(address, b[i:i+20])
		addr := libcommon.BytesToAddress(address)
		result[i/20] = &addr
	}
	return result, nil
}

func (c *Clique) splitTxs(txs types.Transactions, header *types.Header, chain consensus.ChainHeaderReader) (userTxs types.Transactions, systemTxs types.Transactions, err error) {
	userTxs = types.Transactions{}
	systemTxs = types.Transactions{}
	for _, tx := range txs {
		isSystemTx, err2 := c.IsSystemTransaction(tx, header, chain)
		if err2 != nil {
			err = err2
			return
		}
		if isSystemTx {
			systemTxs = append(systemTxs, tx)
		} else {
			userTxs = append(userTxs, tx)
		}
	}
	return
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given.
func (c *Clique) Finalize(_ *chain.Config, header *types.Header, state *state.IntraBlockState,
	txs types.Transactions, _ []*types.Header, receipts types.Receipts, withdrawals []*types.Withdrawal,
	chain consensus.ChainHeaderReader, syscall consensus.SystemCall,
) (types.Transactions, types.Receipts, error) {
	return c.finalize(header, state, txs, receipts, chain, false)
}

func (c *Clique) finalize(header *types.Header, state *state.IntraBlockState, txs types.Transactions, receipts types.Receipts, chain consensus.ChainHeaderReader, mining bool,
) (types.Transactions, types.Receipts, error) {
	if chain.Config().IsChaophraya(header.Number.Uint64()) {

		if chain.Config().ChaophrayaBlock.Cmp(header.Number) == 0 {
			log.Info("⭐️ POS Started", "number", header.Number)
		}
		userTxs, systemTxs, err := c.splitTxs(txs, header, chain)
		if err != nil {
			return nil, nil, err
		}
		txs = userTxs

		number := header.Number.Uint64()

		snap, err := c.Snapshot(chain, number-1, header.ParentHash, nil)
		if err != nil {
			return nil, nil, err
		}

		if needToUpdateValidatorList(c.ChainConfig, header.Number) {
			newValidators, _, err := c.contractClient.GetCurrentValidators(header, state, new(big.Int).SetUint64(number+1))
			if err != nil {
				return nil, nil, err
			}

			validatorsBytes := make([]byte, len(newValidators)*validatorBytesLength)
			for i, validator := range newValidators {
				copy(validatorsBytes[i*validatorBytesLength:], validator.HeaderBytes())
			}

			extraSuffix := len(header.Extra) - ExtraSeal - contractBytesLength
			if !bytes.Equal(header.Extra[ExtraVanity:extraSuffix], validatorsBytes) {
				return nil, nil, errMismatchingSpanValidators
			}
		}

		if isSpanCommitmentBlock(c.ChainConfig, header.Number) {
			var tx types.Transaction
			var receipt *types.Receipt
			if systemTxs, tx, receipt, err = c.commitSpan(c.val, state, header, len(txs), systemTxs, &header.GasUsed, mining, chain); err != nil {
				return nil, nil, err
			} else {
				txs = append(txs, tx)
				receipts = append(receipts, receipt)
			}
		}

		// noturn is only permitted from official node
		if !isInturnDifficulty(header.Difficulty) && header.Coinbase != snap.SystemContracts.OfficialNode {
			return nil, nil, ErrUnauthorizedSigner
		}

		// Begin slashing state update
		if !isInturnDifficulty(header.Difficulty) && header.Coinbase == snap.SystemContracts.OfficialNode {
			log.Debug("ℹ️  Commited by official node", "validator", header.Coinbase, "diff", header.Difficulty, "number", header.Number)
			inturnSigner := snap.getInturnSigner(header.Number.Uint64())
			log.Debug("🗡️  Slashing validator", "signer", inturnSigner, "diff", header.Difficulty, "number", header.Number)
			var tx types.Transaction
			var receipt *types.Receipt

			if len(systemTxs) != 0 && bytes.Equal(systemTxs[0].GetTo().Bytes(), snap.SystemContracts.SlashManager.Bytes()) { // to prevent slashing tx when it should not
				log.Debug("Finalize Slashinggggg2", "to", systemTxs[0].GetTo(), "SlashManager", &snap.SystemContracts.SlashManager)
				if systemTxs, tx, receipt, err = c.slash(inturnSigner, state, header, len(txs), systemTxs, &header.GasUsed, mining, snap); err != nil {
					log.Error("slash validator failed", "block hash", header.Hash(), "address", inturnSigner, "error", err)
				} else {
					if tx != nil { // for the validator was not slashed
						txs = append(txs, tx)
						receipts = append(receipts, receipt)
					}
				}
			}
		}

		if txs, systemTxs, receipts, err = c.distributeIncoming(header.Coinbase, state, header, txs, receipts, systemTxs, &header.GasUsed, mining, snap); err != nil {
			log.Error("distributeIncoming fail", "block hash", header.Hash(), "error", err, "systemTxs", len(systemTxs))
			return nil, nil, err
		}
		if len(systemTxs) > 0 {
			return nil, nil, fmt.Errorf("the length of systemTxs is still %d", len(systemTxs))
		}
		// Re-order receipts so that are in right order
		slices.SortFunc(receipts, func(a, b *types.Receipt) bool { return a.TransactionIndex < b.TransactionIndex })
		return txs, receipts, nil
	}
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	// header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	return txs, receipts, nil
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (c *Clique) FinalizeAndAssemble(chainConfig *chain.Config, header *types.Header, state *state.IntraBlockState,
	txs types.Transactions, uncles []*types.Header, receipts types.Receipts, withdrawals []*types.Withdrawal,
	chain consensus.ChainHeaderReader, syscall consensus.SystemCall, call consensus.Call,
) (*types.Block, types.Transactions, types.Receipts, error) {
	outTxs, outReceipts, err := c.finalize(header, state, txs, receipts, chain, true)
	if err != nil {
		return nil, nil, nil, err
	}
	return types.NewBlock(header, outTxs, nil, outReceipts, withdrawals), outTxs, outReceipts, nil
}

// slash spoiled validators
func (c *Clique) slash(spoiledVal libcommon.Address, state *state.IntraBlockState, header *types.Header,
	txIndex int, systemTxs types.Transactions, usedGas *uint64, mining bool, snap *Snapshot,
) (types.Transactions, types.Transaction, *types.Receipt, error) {
	currentSpan, err := c.contractClient.GetCurrentSpan(header, state)
	if err != nil {
		return systemTxs, nil, nil, err
	}

	slashed, err := c.contractClient.IsSlashed(snap.SystemContracts.SlashManager, spoiledVal, currentSpan, header, state)

	if err != nil {
		return systemTxs, nil, nil, err
	}

	// ignore slash
	if slashed {
		return systemTxs, nil, nil, nil
	}

	return c.contractClient.Slash(snap.SystemContracts.SlashManager, spoiledVal, state, header, txIndex, systemTxs, usedGas, mining, currentSpan)

}

func (c *Clique) distributeIncoming(val libcommon.Address, state *state.IntraBlockState, header *types.Header,
	txs types.Transactions, receipts types.Receipts, systemTxs types.Transactions,
	usedGas *uint64, mining bool, snap *Snapshot) (types.Transactions, types.Transactions, types.Receipts, error) {
	coinbase := header.Coinbase
	balance := state.GetBalance(consensus.SystemAddress).Clone()
	if balance.Cmp(u256.Num0) <= 0 {
		return txs, systemTxs, receipts, nil
	}
	state.SetBalance(consensus.SystemAddress, u256.Num0)
	state.AddBalance(coinbase, balance)

	log.Debug("🪙 distribute to validator", "block hash", header.Hash(), "amount", balance)
	var err error
	var tx types.Transaction
	var receipt *types.Receipt
	if systemTxs, tx, receipt, err = c.contractClient.DistributeToValidator(snap.SystemContracts.StakeManager, balance, state, header, len(txs), systemTxs, usedGas, mining); err != nil {
		return nil, systemTxs, nil, err
	}
	txs = append(txs, tx)
	receipts = append(receipts, receipt)
	return txs, systemTxs, receipts, nil
}

func (c *Clique) commitSpan(val libcommon.Address, state *state.IntraBlockState, header *types.Header,
	txIndex int, systemTxs types.Transactions, usedGas *uint64, mining bool,
	chain consensus.ChainHeaderReader) (types.Transactions, types.Transaction, *types.Receipt, error) {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)

	confirmBlockNr := chain.GetHeaderByNumber(parent.Number.Uint64() - 5)

	newValidators, _ := c.selectNextValidatorSet(parent, confirmBlockNr, state)

	// get validators bytes
	var validators []ctypes.MinimalVal
	for _, val := range newValidators {
		validators = append(validators, val.MinimalVal())
	}
	validatorBytes, _ := rlp.EncodeToBytes(validators)

	return c.contractClient.CommitSpan(state, header, txIndex, systemTxs, usedGas, mining, validatorBytes)
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (c *Clique) Authorize(val libcommon.Address, signFn ctypes.SignerFn) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.val = val
	c.signFn = signFn
	c.contractClient.Inject(c.val, signFn, c)
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (c *Clique) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}, state *state.IntraBlockState) error {

	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if c.config.Period == 0 && len(block.Transactions()) == 0 {
		c.logger.Info("Sealing paused, waiting for transactions")
		return nil
	}
	// Don't hold the signer fields for the entire sealing procedure
	c.lock.RLock()
	val, signFn := c.val, c.signFn
	c.lock.RUnlock()

	// Bail out if we're unauthorized to sign a block
	snap, err := c.Snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	if !chain.Config().IsChaophraya(header.Number.Uint64()) {
		if _, authorized := snap.Signers[val]; !authorized {
			return fmt.Errorf("Clique.Seal: %w", ErrUnauthorizedSigner)
		}
	}
	if chain.Config().IsChaophraya(header.Number.Uint64()) {
		if _, authorized := snap.Signers[val]; !authorized && val != snap.SystemContracts.OfficialNode {
			return ErrUnauthorizedSigner
		}
	}
	// If we're amongst the recent signers, wait for the next block
	if !chain.Config().IsChaophraya(header.Number.Uint64()) {
		for seen, recent := range snap.Recents {
			if recent == val {
				// Signer is among RecentsRLP, only wait if the current block doesn't shift it out
				if limit := uint64(len(snap.Signers)/2 + 1); number < limit || seen > number-limit {
					c.logger.Info("Signed recently, must wait for others")
					return nil
				}
			}
		}
	}
	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := time.Unix(int64(header.Time), 0).Sub(time.Now()) // nolint: gosimple
	// Only be used in PoS
	slashed := false
	// We propose the official validator node which operate by Bitkub Blockchain Technology Co., Ltd.
	// 1. The super node will be the right validator node to seal the block incase of the inturn validator node does not propagate the block in time.
	// The timing of delay, the official will operate to sealing the block and propagate after 1 sec of delay.
	if !chain.Config().IsChaophraya(header.Number.Uint64()) {
		if isNoturnDifficulty(header.Difficulty) {
			// It's not our turn explicitly to sign, delay it a bit
			wiggle := time.Duration(len(snap.Signers)/2+1) * wiggleTime
			delay += time.Duration(rand.Int63n(int64(wiggle)))

			log.Trace("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
		}
	} else {
		if isNoturnDifficulty(header.Difficulty) {
			delay += time.Duration(rand.Int63n(int64(wiggleTime)))
		}
		inturnSigner := snap.getInturnSigner(header.Number.Uint64())
		currentSpan, err := c.contractClient.GetCurrentSpan(header, state)
		if err != nil {
			return err
		}
		if isSpanFirstBlock(c.ChainConfig, header.Number) {
			currentSpan = new(big.Int).Add(currentSpan, libcommon.Big1)
		}
		slashed, err = c.contractClient.IsSlashed(snap.SystemContracts.SlashManager, inturnSigner, currentSpan, header, state)
		if err != nil {
			return err
		}
	}

	// Sign all the things!
	sighash, err := signFn(val, accounts.MimetypeClique, CliqueRLP(header))
	if err != nil {
		return err
	}
	copy(header.Extra[len(header.Extra)-ExtraSeal:], sighash)
	// Wait until sealing is terminated or delay timeout.
	c.logger.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		defer debug.LogPanic()
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}
		if chain.Config().IsChaophraya(header.Number.Uint64()) && (!isInturnDifficulty(header.Difficulty) || slashed) {
			defaultWaitTime := time.Duration(2)
			if slashed {
				defaultWaitTime = time.Duration(0)
			}
			select {
			case <-stop:
				return
			case <-time.After(defaultWaitTime * time.Second):
				if val != snap.SystemContracts.OfficialNode {
					<-stop
					return
				}
			}
		}

		select {
		case results <- block.WithSeal(header):
		default:
			c.logger.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()

	return nil
}

func (c *Clique) GenerateSeal(chain consensus.ChainHeaderReader, currnt, parent *types.Header, call consensus.Call) []byte {
	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have:
// * DIFF_NOTURN(2) if BLOCK_NUMBER % SIGNER_COUNT != SIGNER_INDEX
// * DIFF_INTURN(1) if BLOCK_NUMBER % SIGNER_COUNT == SIGNER_INDEX
func (c *Clique) CalcDifficulty(chain consensus.ChainHeaderReader, _, _ uint64, _ *big.Int, parentNumber uint64, parentHash, _ libcommon.Hash, _ uint64) *big.Int {

	snap, err := c.Snapshot(chain, parentNumber, parentHash, nil)
	if err != nil {
		return nil
	}
	c.lock.RLock()
	val := c.val
	c.lock.RUnlock()
	return calcDifficulty(snap, val)
}

func calcDifficulty(snap *Snapshot, signer libcommon.Address) *big.Int {
	if snap.inturn(snap.Number+1, signer) {
		return new(big.Int).Set(DiffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// SealHash returns the hash of a block prior to it being sealed.
func (c *Clique) SealHash(header *types.Header) libcommon.Hash {
	return SealHash(header)
}

func (c *Clique) IsServiceTransaction(sender libcommon.Address, syscall consensus.SystemCall) bool {
	return false
}

// Close implements consensus.Engine. It's a noop for clique as there are no background threads.
func (c *Clique) Close() error {
	libcommon.SafeClose(c.exitCh)
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (c *Clique) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{
		//{
		//Namespace: "clique",
		//Version:   "1.0",
		//Service:   &API{chain: chain, clique: c},
		//Public:    false,
		//}
	}
}

func (c *Clique) selectNextValidatorSet(parent *types.Header, seedBlock *types.Header, ibs *state.IntraBlockState) ([]ctypes.Validator, error) {
	selectedProducers := make([]ctypes.Validator, 0)

	// seed hash will be from parent hash to seed block hash
	seedBytes := ToBytes32(seedBlock.Hash().Bytes()[:32])
	seed := int64(binary.BigEndian.Uint64(seedBytes[:]))

	r := rand.New(rand.NewSource(seed))

	newValidators, _ := c.contractClient.GetEligibleValidators(parent, ibs)

	// weighted range from validators' voting power
	votingPower := make([]uint64, len(newValidators))
	for idx, validator := range newValidators {
		votingPower[idx] = uint64(validator.VotingPower)
	}

	weightedRanges, totalVotingPower := createWeightedRanges(votingPower)

	for i := uint64(0); i < c.config.Span; i++ {
		/*
			random must be in [1, totalVotingPower] to avoid situation such as
			2 validators with 1 staking power each.
			Weighted range will look like (1, 2)
			Rolling inclusive will have a range of 0 - 2, making validator with staking power 1 chance of selection = 66%
		*/
		targetWeight := randomRangeInclusive(1, totalVotingPower, r)
		index := binarySearch(weightedRanges, targetWeight)
		selectedProducers = append(selectedProducers, *newValidators[index])
	}
	return selectedProducers[:c.config.Span], nil
}

func binarySearch(array []uint64, search uint64) int {
	if len(array) == 0 {
		return -1
	}
	l := 0
	r := len(array) - 1
	for l < r {
		mid := (l + r) / 2
		if array[mid] >= search {
			r = mid
		} else {
			l = mid + 1
		}
	}
	return l
}

// randomRangeInclusive produces unbiased pseudo random in the range [min, max]. Uses rand.Uint64() and can be seeded beforehand.
func randomRangeInclusive(min uint64, max uint64, r *rand.Rand) uint64 {
	if max <= min {
		return max
	}

	rangeLength := max - min + 1
	maxAllowedValue := math.MaxUint64 - math.MaxUint64%rangeLength - 1
	randomValue := r.Uint64()

	// reject anything that is beyond the reminder to avoid bias
	for randomValue >= maxAllowedValue {
		randomValue = r.Uint64()
	}

	return min + randomValue%rangeLength
}

// createWeightedRanges converts array [1, 2, 3] into cumulative form [1, 3, 6]
func createWeightedRanges(weights []uint64) ([]uint64, uint64) {
	weightedRanges := make([]uint64, len(weights))
	totalWeight := uint64(0)
	for i := 0; i < len(weightedRanges); i++ {
		totalWeight += weights[i]
		weightedRanges[i] = totalWeight
	}
	return weightedRanges, totalWeight
}

func ToBytes32(x []byte) [32]byte {
	var y [32]byte
	copy(y[:], x)
	return y
}

func NewCliqueAPI(db kv.RoDB, engine consensus.EngineReader, blockReader services.FullBlockReader) rpc.API {
	var c *Clique
	if casted, ok := engine.(*Clique); ok {
		c = casted
	}

	return rpc.API{
		Namespace: "clique",
		Version:   "1.0",
		Service:   &API{db: db, clique: c, blockReader: blockReader},
		Public:    false,
	}
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash libcommon.Hash) {
	hasher := cryptopool.NewLegacyKeccak256()
	defer cryptopool.ReturnToPoolKeccak256(hasher)

	encodeSigHeader(hasher, header)
	hasher.Sum(hash[:0])
	return hash
}

// CliqueRLP returns the rlp bytes which needs to be signed for the proof-of-authority
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func CliqueRLP(header *types.Header) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header)
	return b.Bytes()
}

func encodeSigHeader(w io.Writer, header *types.Header) {
	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if err := rlp.Encode(w, enc); err != nil {
		panic("can't encode: " + err.Error())
	}
}

// Check whether the given block is in the first block of an epoch
func isOnEpochStart(config *chain.Config, number *big.Int) bool {
	n := number.Uint64()
	return n%config.Clique.Epoch == 0
}

// Check whether the next block of the given block is in proof-of-stake period.
func isNextBlockPoS(config *chain.Config, number *big.Int) bool {
	return config.IsChaophraya((new(big.Int).Add(number, libcommon.Big1)).Uint64())
}

// Check whether the given block is the commitment block (mid-span).
func isSpanCommitmentBlock(config *chain.Config, number *big.Int) bool {
	bigSpan := new(big.Int).SetUint64(config.Clique.Span)

	// number % span
	mod := new(big.Int).Mod(number, bigSpan)
	// span / 2 + 1
	midSpan := new(big.Int).Div(bigSpan, libcommon.Big2)
	midSpan = midSpan.Add(midSpan, libcommon.Big1)

	// is pos && number % span = span / 2 + 1
	return config.IsChaophraya(number.Uint64()) && mod.Cmp(midSpan) == 0
}

// Check whether the given block is the first block of the span.
func isSpanFirstBlock(config *chain.Config, number *big.Int) bool {
	bigSpan := new(big.Int).SetUint64(config.Clique.Span)
	mod := new(big.Int).Mod(number, bigSpan)
	return config.IsChaophraya(number.Uint64()) && mod.Cmp(libcommon.Big0) == 0
}

// Check whether the next block of the given block is the first block of the span.
func isNextBlockASpanFirstBlock(config *chain.Config, number *big.Int) bool {
	bigSpan := new(big.Int).SetUint64(config.Clique.Span)
	nextBlock := new(big.Int).Add(number, libcommon.Big1)
	// (number + 1) % span
	mod := new(big.Int).Mod(nextBlock, bigSpan)
	// is pos && (number + 1) % span == 0
	return config.IsChaophraya(nextBlock.Uint64()) && mod.Cmp(libcommon.Big0) == 0
}

// Check whether geth should update the validator list or not
func needToUpdateValidatorList(config *chain.Config, number *big.Int) bool {
	return isNextBlockASpanFirstBlock(config, number) || isNextBlockExactChaophrayaBlock(config, number)
}

func isNextBlockExactChaophrayaBlock(config *chain.Config, number *big.Int) bool {
	nextBlock := new(big.Int).Add(number, libcommon.Big1)
	return config.IsChaophraya(nextBlock.Uint64()) && config.ChaophrayaBlock.Cmp(nextBlock) == 0
}

// Check whether the given difficulty is the inturn difficulty.
func isInturnDifficulty(diff *big.Int) bool {
	return diff.Cmp(DiffInTurn) == 0
}

// Check whether the given difficulty is the noturn difficulty.
func isNoturnDifficulty(diff *big.Int) bool {
	return diff.Cmp(diffNoTurn) == 0
}

func (c *Clique) snapshots(latest uint64, total int) ([]*Snapshot, error) {
	if total <= 0 {
		return nil, nil
	}

	blockEncoded := dbutils.EncodeBlockNumber(latest)

	tx, err := c.DB.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	cur, err1 := tx.Cursor(kv.CliqueSeparate)
	if err1 != nil {
		return nil, err1
	}
	defer cur.Close()

	res := make([]*Snapshot, 0, total)
	for k, v, err := cur.Seek(blockEncoded); k != nil; k, v, err = cur.Prev() {
		if err != nil {
			return nil, err
		}

		s := new(Snapshot)
		err = json.Unmarshal(v, s)
		if err != nil {
			return nil, err
		}

		s.config = c.ChainConfig
		s.config = c.ChainConfig

		res = append(res, s)

		total--
		if total == 0 {
			break
		}
	}

	return res, nil
}
