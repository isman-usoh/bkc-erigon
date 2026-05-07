# Adding a SetCode-style hardfork to Bitkub erigon

This is the developer reference for adding a new hardfork that overwrites the
bytecode (and optionally the storage) of one or more pre-deployed system
contracts on bkc-mainnet / bkc-testnet. It also covers the overlay machinery
that lets historical RPCs return the correct bytecode after the hardfork ships,
and how to verify both ends with the two CLI tools in `cmd/`.

If you only want a quick checklist, see the skills under `.claude/skills/`. This
doc is the long version: what the moving parts are, *why* they exist, and how
not to break them.

---

## 1. Background — why historical reads need help

Erigon V2 stores history as **forward-projecting changesets keyed by
block-of-application**, not as per-block state snapshots like geth. When the
hardfork applies `state.SetCode(addr, newBytecode)` directly:

1. `kv.PlainContractCode[(addr, incarnation)]` is **overwritten in place** —
   no incarnation bump happens because we did not selfdestruct + recreate.
2. The changeset writer strips the codehash from the BEFORE record on purpose
   (`originalAccountData(original, omitHashes=true)` in
   `core/state/change_set_writer.go`), assuming it can be rederived from
   `kv.PlainContractCode`. For direct SetCode that assumption is false.

Net effect: a historical `eth_getCode(addr, blockBeforeFork)` returns the
*latest* bytecode unless we override the lookup. The override is
`systemContractLookup` in `core/state/plain_readonly.go` and the records that
feed it live in `core/systemcontracts/kub_upgrades.go`. Upstream comment
admits this and points at HistoryV3 (erigon3) as the eventual fix; until then
the overlay is the answer.

The overlay itself reads `PlainState.blockNr - 1` (see
`plain_readonly.go:195-198`) because `PlainState.blockNr = N+1` means "state
at end of block N" — the read-side dual of the changeset's
block-of-application keying. Every other read path uses the same `+1`
convention; off-by-one bugs at fork boundaries are almost always a missed
subtraction in the overlay path.

## 2. Anatomy of a SetCode hardfork

A new hardfork lives in three places.

**A. The instruction builder.**
`consensus/clique/hardfork/<name>/instruction.go` — a function `New(state,
params)` that returns a `hardfork.HardForkInstruction { Storage, Code }`. The
instruction is a pure description; it does not write to the DB itself.
`hardfork/<name>/contract.go` carries the bytecodes as Go literals
(`<Name>V<n>ByteCode`). Pattern lifted directly from `lausanne/` and
`basel/`.

**B. The wiring in clique.**
`consensus/clique/clique.go` calls `c.applyXxxHardfork(...)` from
`Finalize` (see `apply{Lausanne,Basel}Hardfork` near lines 1234 and 1283).
The check is `IsXxx(blockNumber) && header.Number == ChainConfig.XxxBlock`.
`ApplyHardfork` in `consensus/clique/hardfork/hardfork.go` is the single
funnel that turns the instruction into `state.SetState` + `state.SetCode`
calls.

**C. The overlay records.**
`core/systemcontracts/kub_upgrades.go` holds one `[]libcommon.CodeRecord`
slice per (chain, contract). Each entry is `{BlockNumber, CodeHash}` where:
- `BlockNumber` = the fork block at which the new bytecode becomes live
  (i.e. the block the hardfork hook runs at; the new code is the active code
  *from* that block onward).
- `CodeHash` = `keccak256(newBytecode)`.

Records must be in ascending `BlockNumber` order. `PickHistoricalCodeHash`
binary-searches them.

> **Pre-PoS rows.** The first entry per contract should be the original
> deploy block (i.e. the block the contract was first deployed) with the
> codehash of the deploy bytecode. This covers historical reads in the
> window `[deployBlock, firstHardfork-1]`. If you forget the pre-PoS row,
> reads in that window fall through to the broken `kv.PlainContractCode`
> path and return whatever the latest bytecode is.

## 3. Step-by-step: shipping a new hardfork

1. **Solidity / contract side**
   - Compile the new versions of the affected contracts; capture the
     deployed runtime bytecodes (`deployedBytecode`, *not* init code).
   - Compute `keccak256(deployedBytecode)` for each contract — this is the
     `CodeHash` you'll commit.

2. **Add the bytecode literals**
   - Create `consensus/clique/hardfork/<forkname>/contract.go` with
     `var <Name>V<n>ByteCode = libcommon.Hex2Bytes("...")`.

3. **Build the instruction**
   - Create `consensus/clique/hardfork/<forkname>/instruction.go`. Mirror
     `basel/instruction.go`: validate params, build `instruction.Code` and
     any `instruction.Storage` mutations, return.

4. **Wire it into clique**
   - Add a `Xxx` hardfork block to `chain/Config` (mirror `BaselBlock`).
   - In `consensus/clique/clique.go`, add `applyXxxHardfork` and call it
     from `Finalize` at `IsXxx(number) && header.Number == XxxBlock`.

5. **Add overlay records**
   - In `core/systemcontracts/kub_upgrades.go`, append a `{BlockNumber:
     forkBlock, CodeHash: ...}` entry at the end of each affected
     contract's `[]CodeRecord` for both mainnet and testnet.
   - If a contract had no prior record (first time it gets touched by a
     hardfork), prepend the pre-PoS deploy record too. See section 4 if you
     don't have the deploy codehash on hand.

6. **Bump the version**
   - Edit `params/version.go` (`VersionMicro`, `VersionModifier`).

7. **Verify locally then on a deployed archive node**
   - See sections 5 and 6.

## 4. Recovering a deploy codehash you don't have

If a contract was deployed before our records existed and you need its
deploy-block codehash for the pre-PoS row, the **only reliable source is the
archive node itself**. Static decoding of init code is unreliable because
contracts using `immutable` patch the runtime in the constructor before
`RETURN` — the bytecode that actually gets stored differs from any pattern
you can extract from the init code.

Use `debug_traceTransaction` with `callTracer` against an archive RPC. The
top-level `CREATE` call's `output` field is exactly the bytes that get
written to `kv.Code` at deploy time:

```bash
curl -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"debug_traceTransaction",
           "params":["<creation_tx>", {"tracer":"callTracer"}],"id":1}' \
  "$RPC" | jq -r '.result.output' \
  | xxd -r -p | openssl dgst -sha3-256
```

(Or use `crypto.Keccak256` in Go if you want to do it programmatically.)

The creation tx for each system contract can be looked up on
`kubscan.com` / `testnet.kubscan.com` (Blockscout v2 API). For batch deploys
where multiple contracts share one tx, you'll need to walk into the
sub-calls of the trace.

## 5. Verifying with `hardforkverify`

`cmd/hardforkverify` compares `eth_getCode(addr, block)` against every
`CodeRecord` for every chain-relevant system contract. For each record `r` it
generates checks at:

- `latest` — the last record's hash must match `eth_getCode(addr, "latest")`
- `at-fork` — at `r.BlockNumber`
- `after` — at `r.BlockNumber + 1`
- `before` — at `r.BlockNumber - 1` (must equal the previous record)
- `mid-span` — midpoint of `[prev.BlockNumber, r.BlockNumber)`
- `pre-first-record` — at `firstRecord.BlockNumber - 1`, informational

```bash
go run ./cmd/hardforkverify --rpc=http://NODE:8545 --chain=mainnet
go run ./cmd/hardforkverify --rpc=URL_A --rpc-compare=URL_B --chain=mainnet
```

Pass criterion: every contract's CRITICAL row count must be `N/N`. The
report ends with a per-contract `HARDFORKED` / `NOT HARDFORKED` verdict.

The `before` row at the first record (i.e. `firstRecord.BlockNumber - 1`,
which is `deployBlock - 1` if you did the pre-PoS row right) is
informational because the contract often did not exist yet there — empty
code is correct. We keep the row anyway because it surfaces overlay
regressions for free (it caught the v1.2.1 pre-Basel panic on NftContract).

Things that fail with this tool:

- **Wrong `CodeHash` in the records** — observed hash doesn't match
  expected. If the hash *also* doesn't appear in `kv.Code` on the node, the
  RPC returns empty (`-`). Re-derive the hash via `debug_traceTransaction`.
- **Off-by-one in the overlay** — the `before` row returns the *next*
  record's hash. Check `plain_readonly.go:195-198` (`overlayBlock = blockNr
  - 1`) is intact.
- **Missing pre-PoS row** — pre-fork reads of a contract that has only one
  record return latest bytecode instead of the historical deploy bytecode.

## 6. Verifying with `tracereplayverify`

`hardforkverify` only exercises `eth_getCode`. `tracereplayverify` is the
end-to-end variant: it replays historical blocks via
`trace_replayBlockTransactions`, which forces the EVM to actually execute
the synthetic `commitSpan` system tx using the bytecode the overlay returns.
A broken overlay panics here (index-out-of-range) where `eth_getCode` would
just silently return wrong bytes.

```bash
go run ./cmd/tracereplayverify --rpc=http://NODE:8545
```

Block selection is automatic and derived from `SystemContractCodeLookup`:

1. `F-1, F, F+1` for every fork block of every kub system contract
2. Span-commit straddles (mid-span blocks before/after each fork)
3. Two control blocks far from any fork

Pass criterion: every block returns a non-error JSON-RPC response. Any
`FAIL` row points at a real bug.

This tool currently runs against mainnet only. Add a `testnetBlocks()`
mirror if you need testnet coverage.

## 7. Common gotchas

- **Don't reuse `+1` blindly.** `PlainState.blockNr` is "state at end of
  block N" where the field equals N+1. Inside the overlay we go back to N
  with `blockNr - 1`. If you add a new historical-read path, follow the
  same convention or you'll re-introduce the off-by-one.
- **Records are append-only.** Editing a historical entry's hash after
  release breaks every node syncing from before the change. Add a new entry
  for a new hardfork; never rewrite an old one.
- **Storage changes during the hardfork show up in the changeset normally.**
  Storage history is keyed by `(addr, incarnation, slot)` and not stripped.
  The overlay only exists for the codehash side.
- **Do not switch to selfdestruct + recreate to fix the overlay.** It would
  bump incarnation and remove the need for the overlay, but it changes the
  state-root calculation — that's a *coordinated* hardfork with every
  client validating the chain, not a node-internal change.
- **`pre-first-record` row staying empty is correct** when the contract
  didn't exist at `deployBlock - 1`. It is `mustPass: false` and reported
  as `·` so it never gates verdict.

## 8. The eventual fix: HistoryV3

Upstream's note (in `core/systemcontracts/upgrade.go`) calls this overlay a
workaround until HistoryV3 lands. HistoryV3 redesigns the changeset layout
to preserve codehash per-block-per-address; once we migrate, the entire
`systemContractLookup` layer can be deleted. Tracking that migration is a
much bigger project — out of scope here.
