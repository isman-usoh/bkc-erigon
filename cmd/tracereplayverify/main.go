// tracereplayverify exercises the system-contract-overlay fix end-to-end by
// replaying historical Bitkub blocks through trace_replayBlockTransactions
// against an archive RPC endpoint. Where hardforkverify only checks that
// eth_getCode returns the right bytecode at fork boundaries, this command
// makes the EVM actually execute the synthetic commitSpan system tx — the
// real-world consumer of the overlay — at every kub code-record boundary
// and at the surrounding mid-span commitment blocks.
//
// Pass criterion is simple: every block returns a non-error JSON-RPC
// response. The unfixed node panics with index-out-of-range at the basel
// boundary; a fixed node replies cleanly across all blocks.
//
// Usage:
//
//	go run ./cmd/tracereplayverify --rpc=http://NODE
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/core/systemcontracts"
	"github.com/ledgerwatch/erigon/params/networkname"
)

// ----- block selection ----------------------------------------------------

type blockClass int

const (
	classBoundary   blockClass = iota // F-1, F, F+1 around a code-record fork block
	classSpanCommit                   // a mid-span commitment block (commitSpan system tx)
	classControl                      // a normal block far from any boundary
)

func (c blockClass) String() string {
	switch c {
	case classBoundary:
		return "boundary"
	case classSpanCommit:
		return "span-commit"
	case classControl:
		return "control"
	}
	return "?"
}

type testBlock struct {
	number uint64
	class  blockClass
	label  string
}

// mainnetContractNames / testnetContractNames map per-chain system-contract
// addresses to friendly labels for the report. Sourced from the
// systemcontracts package (same source of truth as hardforkverify).
var mainnetContractNames = map[libcommon.Address]string{
	systemcontracts.KubPosStakeManagerMainnet:        "StakeManager",
	systemcontracts.KubPosSlashManagerMainnet:        "SlashManager",
	systemcontracts.KubPosStakeManagerStorageMainnet: "StakeManagerStorage",
	systemcontracts.KubPosBKCValidatorSetMainnet:     "BKCValidatorSet",
	systemcontracts.KubPosNftContractMainnet:         "NftContract",
}

var testnetContractNames = map[libcommon.Address]string{
	systemcontracts.KubPosStakeManagerTestnet:        "StakeManager",
	systemcontracts.KubPosSlashManagerTestnet:        "SlashManager",
	systemcontracts.KubPosStakeManagerStorageTestnet: "StakeManagerStorage",
	systemcontracts.KubPosBKCValidatorSetTestnet:     "BKCValidatorSet",
	systemcontracts.KubPosNftContractTestnet:         "NftContract",
}

// chainBlocks: deterministic, programmatically-derived coverage for one chain.
//
// 1. Per-contract boundary triplets: for every CodeRecord across every kub
//    system contract in core/systemcontracts.SystemContractCodeLookup for
//    chainName, test F-1, F, F+1. This walks each contract's full upgrade
//    timeline.
// 2. Span-commit straddles: at each unique fork block F, also test the
//    nearest mid-span (N%50==26) blocks before and after F. That's where
//    BKCValidatorSet.commitSpan is actually invoked under the contract
//    version in force at that block.
// 3. Caller-supplied control blocks far from any fork to confirm the
//    normal path under each era's contract version.
func chainBlocks(chainName string, contractNames map[libcommon.Address]string, controls []testBlock) []testBlock {
	lookup := systemcontracts.SystemContractCodeLookup[chainName]

	// Sort contracts by friendly name for stable output order.
	addrs := make([]libcommon.Address, 0, len(lookup))
	for a := range lookup {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool {
		return contractNames[addrs[i]] < contractNames[addrs[j]]
	})

	type key struct {
		block uint64
		label string
	}
	seen := map[key]bool{}
	var bs []testBlock
	add := func(b testBlock) {
		k := key{b.number, b.label}
		if seen[k] {
			return
		}
		seen[k] = true
		bs = append(bs, b)
	}

	// (1) Per-contract code-record boundaries.
	uniqueForks := map[uint64]bool{}
	for _, addr := range addrs {
		name := contractNames[addr]
		if name == "" {
			name = addr.Hex()
		}
		for _, r := range lookup[addr] {
			f := r.BlockNumber
			uniqueForks[f] = true
			add(testBlock{f - 1, classBoundary, name + "-pre"})
			add(testBlock{f, classBoundary, name + "-fork"})
			add(testBlock{f + 1, classBoundary, name + "-post"})
		}
	}

	// (2) Span-commit straddles for each unique fork block.
	prevSpan := func(n uint64) uint64 {
		m := (n / 50) * 50
		if m+26 < n {
			return m + 26
		}
		if m < 50 {
			return 0
		}
		return m - 50 + 26
	}
	nextSpan := func(n uint64) uint64 {
		m := (n / 50) * 50
		if m+26 >= n {
			return m + 26
		}
		return m + 50 + 26
	}
	forks := make([]uint64, 0, len(uniqueForks))
	for f := range uniqueForks {
		forks = append(forks, f)
	}
	sort.Slice(forks, func(i, j int) bool { return forks[i] < forks[j] })
	for _, f := range forks {
		add(testBlock{prevSpan(f), classSpanCommit, fmt.Sprintf("span-before-%d", f)})
		add(testBlock{nextSpan(f), classSpanCommit, fmt.Sprintf("span-after-%d", f)})
	}

	// (3) Control blocks: caller-supplied normal mid-region commitSpan blocks.
	for _, c := range controls {
		add(c)
	}

	// Final sort: by block number for clean chronological output.
	sort.SliceStable(bs, func(i, j int) bool { return bs[i].number < bs[j].number })
	return bs
}

// mainnetBlocks: full block coverage for bkc-mainnet. Control blocks are
// commitSpan blocks (N%50==26) chosen from the middle of each post-deploy era.
func mainnetBlocks() []testBlock {
	return chainBlocks(networkname.BkcMainnetChainName, mainnetContractNames, []testBlock{
		{14_500_026, classControl, "control-mid-chaophraya-era"},
		{28_000_076, classControl, "control-mid-lausanne-era"},
	})
}

// testnetBlocks: full block coverage for bkc-testnet. Control blocks are
// commitSpan blocks (N%50==26) chosen from the middle of each post-deploy era
// on testnet (deploy=11712666, Lausanne=22835041, Basel=27929040).
func testnetBlocks() []testBlock {
	return chainBlocks(networkname.BkcTestnetChainName, testnetContractNames, []testBlock{
		{17_000_026, classControl, "control-mid-pre-pos-era"},
		{25_000_026, classControl, "control-mid-lausanne-era"},
	})
}

// ----- config & main ------------------------------------------------------

type config struct {
	rpc       string
	chain     string
	insecure  bool
	timeout   time.Duration
	traceType string
}

func main() {
	var cfg config
	flag.StringVar(&cfg.rpc, "rpc", "", "RPC URL (required)")
	flag.StringVar(&cfg.chain, "chain", "mainnet", "chain to verify: mainnet | testnet")
	flag.BoolVar(&cfg.insecure, "insecure", false, "skip TLS certificate verification")
	flag.DurationVar(&cfg.timeout, "timeout", 60*time.Second, "per-request timeout")
	flag.StringVar(&cfg.traceType, "trace-type", "trace", "trace type to request (e.g. trace, vmTrace, stateDiff). Comma-separate for multiple.")
	flag.Parse()

	if cfg.rpc == "" {
		fmt.Fprintln(os.Stderr, "error: --rpc is required")
		flag.Usage()
		os.Exit(2)
	}
	var blocks []testBlock
	var chainDisplay string
	switch strings.ToLower(cfg.chain) {
	case "mainnet", "bkc-mainnet":
		blocks = mainnetBlocks()
		chainDisplay = networkname.BkcMainnetChainName
	case "testnet", "bkc-testnet":
		blocks = testnetBlocks()
		chainDisplay = networkname.BkcTestnetChainName
	default:
		fmt.Fprintln(os.Stderr, "error: --chain must be mainnet or testnet")
		os.Exit(2)
	}

	traceTypes := splitCSV(cfg.traceType)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout*time.Duration(len(blocks)+5))
	defer cancel()

	client := newClient(cfg.rpc, cfg.insecure, cfg.timeout)
	clientVer := client.clientVersion(ctx)

	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf(" trace_replayBlockTransactions verification — chain: %s\n", chainDisplay)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf(" RPC:     %s\n version: %s\n\n", cfg.rpc, clientVer)
	fmt.Printf(" %-26s %-12s %-12s %-10s %s\n", "label", "block", "class", "status", "detail")
	fmt.Println(strings.Repeat("-", 80))

	failed := 0
	for _, b := range blocks {
		size, err := client.traceReplayBlock(ctx, b.number, traceTypes)
		if err != nil {
			failed++
			fmt.Printf(" ✗ %-24s %-12d %-12s %-10s %s\n",
				b.label, b.number, b.class.String(), "FAIL", truncate(err.Error(), 60))
		} else {
			fmt.Printf(" ✓ %-24s %-12d %-12s %-10s %d bytes\n",
				b.label, b.number, b.class.String(), "OK", size)
		}
	}

	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf(" SUMMARY: %d/%d blocks responded without error\n", len(blocks)-failed, len(blocks))
	if failed > 0 {
		fmt.Println(" OVERALL: ❌ at least one block errored — system-contract overlay regression suspected.")
		os.Exit(1)
	}
	fmt.Println(" OVERALL: ✅ every block replied cleanly across boundary, span-commit, and control blocks.")
}

// ----- RPC ----------------------------------------------------------------

type rpcClient struct {
	url  string
	http *http.Client
}

func newClient(url string, insecure bool, timeout time.Duration) *rpcClient {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &rpcClient{url: url, http: &http.Client{Transport: tr, Timeout: timeout}}
}

type rpcReq struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

func (c *rpcClient) callRaw(ctx context.Context, method string, params []interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(rpcReq{JSONRPC: "2.0", Method: method, Params: params, ID: 1})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode: %v: %s", err, truncate(string(raw), 200))
	}
	if env.Error != nil {
		return nil, fmt.Errorf("rpc %d: %s", env.Error.Code, env.Error.Message)
	}
	return env.Result, nil
}

// traceReplayBlock returns the response size in bytes on success.
func (c *rpcClient) traceReplayBlock(ctx context.Context, block uint64, traceTypes []string) (int, error) {
	tag := fmt.Sprintf("0x%x", block)
	tt := make([]interface{}, len(traceTypes))
	for i, s := range traceTypes {
		tt[i] = s
	}
	res, err := c.callRaw(ctx, "trace_replayBlockTransactions", []interface{}{tag, tt})
	if err != nil {
		return 0, err
	}
	return len(res), nil
}

func (c *rpcClient) clientVersion(ctx context.Context) string {
	res, err := c.callRaw(ctx, "web3_clientVersion", []interface{}{})
	if err != nil {
		return "unknown"
	}
	var s string
	if err := json.Unmarshal(res, &s); err != nil {
		return "unknown"
	}
	return s
}

// ----- helpers ------------------------------------------------------------

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
