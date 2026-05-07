// hardforkverify verifies that a remote archive RPC endpoint reports the
// historically-correct bytecode for each Bitkub system contract at every
// CodeRecord checkpoint declared in core/systemcontracts/kub_upgrades.go.
//
// Scope: Kub protocol changes only (StakeManager, SlashManager,
// StakeManagerStorage, NftContract, BKCValidatorSet). Ethereum/BSC
// hardforks are intentionally out of scope.
//
// Run manually:
//
//	go run ./cmd/hardforkverify --rpc=https://... --chain=mainnet
//	go run ./cmd/hardforkverify --rpc=URL_A --rpc-compare=URL_B --chain=mainnet
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/ledgerwatch/erigon/crypto"
	"github.com/ledgerwatch/erigon/params/networkname"
)

type config struct {
	rpc        string
	rpcCompare string
	chain      string
	insecure   bool
	timeout    time.Duration
	verbose    bool
	latestOnly bool
	contract   string
	jsonOut    bool
}

func main() {
	var cfg config
	flag.StringVar(&cfg.rpc, "rpc", "", "primary RPC URL (required)")
	flag.StringVar(&cfg.rpcCompare, "rpc-compare", "", "second RPC URL for cross-node consistency check (optional)")
	flag.StringVar(&cfg.chain, "chain", "", "chain to verify: mainnet | testnet (required)")
	flag.BoolVar(&cfg.insecure, "insecure", false, "skip TLS certificate verification")
	flag.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "per-request timeout")
	flag.BoolVar(&cfg.verbose, "verbose", false, "print every check, not just failures")
	flag.BoolVar(&cfg.latestOnly, "latest-only", false, "only verify the latest record per contract")
	flag.StringVar(&cfg.contract, "contract", "", "filter to a single contract by name (e.g. StakeManager)")
	flag.BoolVar(&cfg.jsonOut, "json", false, "emit machine-readable JSON instead of a table")
	flag.Parse()

	if cfg.rpc == "" || cfg.chain == "" {
		fmt.Fprintln(os.Stderr, "error: --rpc and --chain are required")
		flag.Usage()
		os.Exit(2)
	}

	chainName, names, lookup, err := resolveChain(cfg.chain)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	checks, err := buildChecks(lookup, names, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	client := newClient(cfg.rpc, cfg.insecure, cfg.timeout)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout*time.Duration(len(checks)+5))
	defer cancel()

	primaryVer := client.clientVersion(ctx)
	results := runChecks(ctx, client, checks)

	var compareResults []result
	var compareVer string
	if cfg.rpcCompare != "" {
		client2 := newClient(cfg.rpcCompare, cfg.insecure, cfg.timeout)
		compareVer = client2.clientVersion(ctx)
		compareResults = runChecks(ctx, client2, checks)
	}

	failed := report(cfg, chainName, results, compareResults, primaryVer, compareVer)
	if failed > 0 {
		os.Exit(1)
	}
}

// ----- chain resolution ---------------------------------------------------

func resolveChain(short string) (
	displayName string,
	names map[libcommon.Address]string,
	lookup map[libcommon.Address][]libcommon.CodeRecord,
	err error,
) {
	switch strings.ToLower(short) {
	case "mainnet", "bkc-mainnet":
		displayName = networkname.BkcMainnetChainName
		names = map[libcommon.Address]string{
			systemcontracts.KubPosStakeManagerMainnet:        "StakeManager",
			systemcontracts.KubPosSlashManagerMainnet:        "SlashManager",
			systemcontracts.KubPosStakeManagerStorageMainnet: "StakeManagerStorage",
			systemcontracts.KubPosBKCValidatorSetMainnet:     "BKCValidatorSet",
			systemcontracts.KubPosNftContractMainnet:         "NftContract",
		}
	case "testnet", "bkc-testnet":
		displayName = networkname.BkcTestnetChainName
		names = map[libcommon.Address]string{
			systemcontracts.KubPosStakeManagerTestnet:        "StakeManager",
			systemcontracts.KubPosSlashManagerTestnet:        "SlashManager",
			systemcontracts.KubPosStakeManagerStorageTestnet: "StakeManagerStorage",
			systemcontracts.KubPosBKCValidatorSetTestnet:     "BKCValidatorSet",
			systemcontracts.KubPosNftContractTestnet:         "NftContract",
		}
	default:
		return "", nil, nil, fmt.Errorf("unknown chain %q (expected mainnet or testnet)", short)
	}
	lookup = systemcontracts.SystemContractCodeLookup[displayName]
	if lookup == nil {
		return "", nil, nil, fmt.Errorf("no SystemContractCodeLookup entry for %s", displayName)
	}
	return displayName, names, lookup, nil
}

// ----- check generation ---------------------------------------------------

type check struct {
	contract string
	address  libcommon.Address
	block    uint64
	expected libcommon.Hash // zero means "informational; no expectation"
	label    string
	mustPass bool
}

func buildChecks(
	lookup map[libcommon.Address][]libcommon.CodeRecord,
	names map[libcommon.Address]string,
	cfg config,
) ([]check, error) {
	// Stable iteration: sort addresses by name for deterministic output.
	type entry struct {
		addr    libcommon.Address
		name    string
		records []libcommon.CodeRecord
	}
	var entries []entry
	for addr, recs := range lookup {
		name := names[addr]
		if name == "" {
			name = addr.Hex()
		}
		if cfg.contract != "" && !strings.EqualFold(cfg.contract, name) {
			continue
		}
		entries = append(entries, entry{addr, name, recs})
	}
	if len(entries) == 0 {
		return nil, errors.New("no contracts matched the filter")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	var checks []check
	for _, e := range entries {
		recs := e.records
		// "latest" check: query the most recent record's expected hash at `latest`.
		if len(recs) > 0 {
			last := recs[len(recs)-1]
			checks = append(checks, check{
				contract: e.name, address: e.addr, block: 0, // 0 => "latest"
				expected: last.CodeHash, label: "latest", mustPass: true,
			})
		}
		if cfg.latestOnly {
			continue
		}

		for i, r := range recs {
			// at-fork
			checks = append(checks, check{
				contract: e.name, address: e.addr, block: r.BlockNumber,
				expected: r.CodeHash, label: "at-fork", mustPass: true,
			})
			// just-after fork
			checks = append(checks, check{
				contract: e.name, address: e.addr, block: r.BlockNumber + 1,
				expected: r.CodeHash, label: "after", mustPass: true,
			})
			if i > 0 {
				prev := recs[i-1]
				// just-before fork: must match the previous record. eth_getCode at
				// (forkBlock-1) is a query for state at that historical block, and
				// the answer must be the bytecode in force at that block. Any
				// overlay off-by-one that returns the next record's hash here is a
				// real correctness bug, not a cosmetic boundary artifact.
				checks = append(checks, check{
					contract: e.name, address: e.addr, block: r.BlockNumber - 1,
					expected: prev.CodeHash, label: "before", mustPass: true,
				})
				// midpoint of [prev, this) should hold previous record
				mid := prev.BlockNumber + (r.BlockNumber-prev.BlockNumber)/2
				checks = append(checks, check{
					contract: e.name, address: e.addr, block: mid,
					expected: prev.CodeHash, label: "mid-span", mustPass: true,
				})
			} else if r.BlockNumber > 0 {
				// pre-first-record: informational only. The contract may have been
				// pre-deployed normally. Reporting it surfaces overlay-induced
				// regressions (e.g. the v1.2.1 pre-Basel panic on NftContract).
				checks = append(checks, check{
					contract: e.name, address: e.addr, block: r.BlockNumber - 1,
					expected: libcommon.Hash{}, label: "pre-first-record", mustPass: false,
				})
			}
		}
	}
	return checks, nil
}

// ----- RPC client ---------------------------------------------------------

type rpcClient struct {
	url    string
	http   *http.Client
}

func newClient(url string, insecure bool, timeout time.Duration) *rpcClient {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &rpcClient{
		url:  url,
		http: &http.Client{Transport: tr, Timeout: timeout},
	}
}

type rpcReq struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type rpcResp struct {
	Result string `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *rpcClient) call(ctx context.Context, method string, params []interface{}) (string, error) {
	body, err := json.Marshal(rpcReq{JSONRPC: "2.0", Method: method, Params: params, ID: 1})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var out rpcResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("decode: %v: %s", err, truncate(string(raw), 200))
	}
	if out.Error != nil {
		return "", fmt.Errorf("rpc %d: %s", out.Error.Code, out.Error.Message)
	}
	return out.Result, nil
}

func (c *rpcClient) getCode(ctx context.Context, addr libcommon.Address, block uint64) ([]byte, error) {
	tag := "latest"
	if block != 0 {
		tag = fmt.Sprintf("0x%x", block)
	}
	res, err := c.call(ctx, "eth_getCode", []interface{}{addr.Hex(), tag})
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(res, "0x") {
		return nil, fmt.Errorf("unexpected result: %q", truncate(res, 80))
	}
	return hex.DecodeString(res[2:])
}

func (c *rpcClient) clientVersion(ctx context.Context) string {
	res, err := c.call(ctx, "web3_clientVersion", []interface{}{})
	if err != nil {
		return "unknown"
	}
	return res
}

// ----- execution & reporting ----------------------------------------------

type result struct {
	check    check
	observed libcommon.Hash
	codeLen  int
	rpcErr   error
}

func (r result) status() string {
	if r.rpcErr != nil {
		if r.check.mustPass {
			return "ERROR"
		}
		return "INFO-ERR"
	}
	if !r.check.mustPass {
		// Informational checks: distinguish "matches expectation" from
		// "differs but does not gate verdict" so operators can spot the
		// cosmetic overlay off-by-one on `before` rows.
		if r.check.expected == (libcommon.Hash{}) || r.observed == r.check.expected {
			return "INFO"
		}
		return "DIFF"
	}
	if r.observed == r.check.expected {
		return "PASS"
	}
	return "FAIL"
}

func runChecks(ctx context.Context, c *rpcClient, checks []check) []result {
	out := make([]result, len(checks))
	for i, ck := range checks {
		code, err := c.getCode(ctx, ck.address, ck.block)
		r := result{check: ck, rpcErr: err}
		if err == nil {
			r.codeLen = len(code)
			if len(code) > 0 {
				r.observed = crypto.Keccak256Hash(code)
			}
		}
		out[i] = r
	}
	return out
}

// statusIcon returns a one-glyph status indicator for a check result.
func statusIcon(s string) string {
	switch s {
	case "PASS":
		return "✓"
	case "FAIL":
		return "✗"
	case "ERROR":
		return "!"
	case "DIFF":
		return "~"
	case "INFO":
		return "·"
	case "INFO-ERR":
		return "·"
	}
	return "?"
}

// verdict computes a contract-level yes/no based on critical (mustPass) checks.
// Returns (ok, criticalPass, criticalTotal, infoPass, infoTotal).
func verdict(rs []result) (bool, int, int, int, int) {
	var cP, cT, iP, iT int
	ok := true
	for _, r := range rs {
		if r.check.mustPass {
			cT++
			if r.status() == "PASS" {
				cP++
			} else {
				ok = false
			}
		} else {
			iT++
			if r.status() == "INFO" {
				iP++
			}
		}
	}
	return ok, cP, cT, iP, iT
}

func report(cfg config, chainName string, results, compare []result, primaryVer, compareVer string) int {
	if cfg.jsonOut {
		return reportJSON(results, compare)
	}

	hasCompare := cfg.rpcCompare != ""
	primaryLabel := "PRIMARY"
	compareLabel := "COMPARE"

	// Header.
	fmt.Println(strings.Repeat("=", 78))
	fmt.Printf(" Hardfork verification — chain: %s\n", chainName)
	fmt.Println(strings.Repeat("=", 78))
	fmt.Printf(" %-8s %s\n", primaryLabel+":", cfg.rpc)
	fmt.Printf(" %-8s %s\n", "version", primaryVer)
	if hasCompare {
		fmt.Printf(" %-8s %s\n", compareLabel+":", cfg.rpcCompare)
		fmt.Printf(" %-8s %s\n", "version", compareVer)
	}
	fmt.Println()

	// Group results by contract.
	type group struct {
		name    string
		address libcommon.Address
		rows    []result
		cmpRows []result
	}
	groups := make([]*group, 0)
	idx := map[string]*group{}
	for i, r := range results {
		g := idx[r.check.contract]
		if g == nil {
			g = &group{name: r.check.contract, address: r.check.address}
			idx[r.check.contract] = g
			groups = append(groups, g)
		}
		g.rows = append(g.rows, r)
		if hasCompare && i < len(compare) {
			g.cmpRows = append(g.cmpRows, compare[i])
		}
	}

	// Per-contract detail blocks.
	failed := 0
	for _, g := range groups {
		// Block header.
		fmt.Printf("──── %s  %s\n", g.name, g.address.Hex())
		// Column header.
		if hasCompare {
			fmt.Printf("    %-17s %-11s %-18s   %s %-22s   %s %s\n",
				"label", "block", "expected", " ", primaryLabel, " ", compareLabel)
		} else {
			fmt.Printf("    %-17s %-11s %-18s   %s %s\n",
				"label", "block", "expected", " ", primaryLabel)
		}
		for j, r := range g.rows {
			blkStr := "latest"
			if r.check.block != 0 {
				blkStr = fmt.Sprintf("%d", r.check.block)
			}
			exp := truncHash(r.check.expected)
			pSt := r.status()
			pObs := truncHash(r.observed)
			if r.rpcErr != nil {
				pObs = "ERR " + truncate(r.rpcErr.Error(), 22)
			}
			pIcon := statusIcon(pSt)
			if pSt == "FAIL" || pSt == "ERROR" {
				failed++
			}
			if hasCompare && j < len(g.cmpRows) {
				c := g.cmpRows[j]
				cSt := c.status()
				cObs := truncHash(c.observed)
				if c.rpcErr != nil {
					cObs = "ERR " + truncate(c.rpcErr.Error(), 22)
				}
				cIcon := statusIcon(cSt)
				if cSt == "FAIL" || cSt == "ERROR" {
					failed++
				}
				fmt.Printf("    %-17s %-11s %-18s   %s %-22s   %s %s\n",
					r.check.label, blkStr, exp, pIcon, pObs, cIcon, cObs)
			} else {
				fmt.Printf("    %-17s %-11s %-18s   %s %s\n",
					r.check.label, blkStr, exp, pIcon, pObs)
			}
		}
		fmt.Println()
	}

	// Final summary table (the yay/nay).
	fmt.Println(strings.Repeat("─", 78))
	fmt.Println(" SUMMARY — hardfork state per contract")
	fmt.Println(strings.Repeat("─", 78))
	if hasCompare {
		fmt.Printf("  %-22s %-16s %-18s %s\n", "CONTRACT", "CRITICAL", primaryLabel, compareLabel)
	} else {
		fmt.Printf("  %-22s %-16s %s\n", "CONTRACT", "CRITICAL", primaryLabel)
	}
	allOK := true
	allOKCmp := true
	for _, g := range groups {
		okP, cP, cT, _, _ := verdict(g.rows)
		critStr := fmt.Sprintf("%d/%d", cP, cT)
		pVerdict := "✅ HARDFORKED"
		if !okP {
			pVerdict = "❌ NOT HARDFORKED"
			allOK = false
		}
		if hasCompare {
			okC, ccP, ccT, _, _ := verdict(g.cmpRows)
			cVerdict := "✅ HARDFORKED"
			if !okC {
				cVerdict = "❌ NOT HARDFORKED"
				allOKCmp = false
			}
			critStr = fmt.Sprintf("p=%d/%d c=%d/%d", cP, cT, ccP, ccT)
			fmt.Printf("  %-22s %-16s %-18s %s\n", g.name, critStr, pVerdict, cVerdict)
		} else {
			fmt.Printf("  %-22s %-16s %s\n", g.name, critStr, pVerdict)
		}
	}
	fmt.Println(strings.Repeat("─", 78))
	overall := "✅ all hardforks correctly applied"
	if !allOK || (hasCompare && !allOKCmp) {
		overall = "❌ one or more contracts are not correctly hardforked"
	}
	fmt.Printf(" OVERALL: %s\n", overall)
	if failed > 0 {
		fmt.Printf(" (%d row-level failures across %d total checks)\n", failed, len(results)+len(compare))
	}
	fmt.Println()
	fmt.Println(" Legend: ✓ pass  ✗ fail  ! rpc-error  ~ informational diff  · informational")
	if !cfg.verbose {
		// Note: with current layout we always print all rows. Keeping --verbose flag
		// for backwards compatibility; it does not change human output.
	}
	return failed
}

type jsonResult struct {
	Contract string `json:"contract"`
	Address  string `json:"address"`
	Block    uint64 `json:"block"`
	Label    string `json:"label"`
	Status   string `json:"status"`
	Expected string `json:"expected,omitempty"`
	Observed string `json:"observed,omitempty"`
	CodeLen  int    `json:"code_len"`
	Error    string `json:"error,omitempty"`
	Compare  *struct {
		Status   string `json:"status"`
		Observed string `json:"observed,omitempty"`
		Error    string `json:"error,omitempty"`
	} `json:"compare,omitempty"`
}

func reportJSON(results, compare []result) int {
	failed := 0
	out := make([]jsonResult, len(results))
	for i, r := range results {
		jr := jsonResult{
			Contract: r.check.contract,
			Address:  r.check.address.Hex(),
			Block:    r.check.block,
			Label:    r.check.label,
			Status:   r.status(),
			Expected: optionalHash(r.check.expected),
			Observed: optionalHash(r.observed),
			CodeLen:  r.codeLen,
		}
		if r.rpcErr != nil {
			jr.Error = r.rpcErr.Error()
		}
		if jr.Status == "FAIL" || jr.Status == "ERROR" {
			failed++
		}
		if i < len(compare) {
			c2 := compare[i]
			cmp := struct {
				Status   string `json:"status"`
				Observed string `json:"observed,omitempty"`
				Error    string `json:"error,omitempty"`
			}{Status: c2.status(), Observed: optionalHash(c2.observed)}
			if c2.rpcErr != nil {
				cmp.Error = c2.rpcErr.Error()
			}
			if c2.observed != r.observed && r.check.mustPass && r.rpcErr == nil && c2.rpcErr == nil {
				failed++
			}
			jr.Compare = &cmp
		}
		out[i] = jr
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	return failed
}

// ----- helpers ------------------------------------------------------------

func truncHash(h libcommon.Hash) string {
	if h == (libcommon.Hash{}) {
		return "-"
	}
	s := h.Hex()
	return s[:10] + ".." + s[len(s)-4:]
}

func optionalHash(h libcommon.Hash) string {
	if h == (libcommon.Hash{}) {
		return ""
	}
	return h.Hex()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
