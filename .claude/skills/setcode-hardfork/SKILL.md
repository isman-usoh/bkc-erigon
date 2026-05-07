---
name: setcode-hardfork
description: Add a new SetCode-style hardfork (overwrite system-contract bytecode at a fork block) on bkc-mainnet/testnet, including the historical-read overlay records.
---

# Adding a SetCode hardfork

Use this skill when the user asks to "add a hardfork", "ship a new
contract upgrade", "bump the system contracts at block X", or similar.

For the full rationale and the read-side overlay theory, read
`docs/hardfork/setcode.md`. This skill is the action checklist.

## Files you will touch

| Purpose | Path |
|---|---|
| Bytecode literals | `consensus/clique/hardfork/<forkname>/contract.go` |
| Storage/code instruction | `consensus/clique/hardfork/<forkname>/instruction.go` |
| Hook wiring | `consensus/clique/clique.go` (mirror `applyBaselHardfork`) |
| Chain config field | wherever `BaselBlock` is declared in chain config |
| Overlay records | `core/systemcontracts/kub_upgrades.go` |
| Version bump | `params/version.go` |

## Steps

1. **Bytecode in.** Drop new runtime bytecodes into
   `hardfork/<forkname>/contract.go` as `var <Name>V<n>ByteCode = libcommon.Hex2Bytes("...")`.
2. **Instruction.** Mirror `consensus/clique/hardfork/basel/instruction.go`:
   validate addresses, populate `instruction.Code` (always) and
   `instruction.Storage` (if storage layout changes), return.
3. **Wire.** Add `applyXxxHardfork` in `consensus/clique/clique.go` and
   call it from `Finalize` guarded by `IsXxx(number) && header.Number == XxxBlock`.
4. **Records — appended entry.** For each affected contract, append
   `{BlockNumber: forkBlock, CodeHash: keccak256(newBytecode)}` to its
   `[]CodeRecord` slice in `core/systemcontracts/kub_upgrades.go`. Maintain
   ascending order. Do this for **both mainnet and testnet** record slices.
5. **Records — pre-PoS row (if missing).** If the contract has no prior
   record, **prepend** `{BlockNumber: deployBlock, CodeHash: deployHash}`
   so historical reads in `[deployBlock, firstHardfork-1]` resolve
   correctly. If you don't have `deployHash`, recover it via
   `debug_traceTransaction` (see "Recovering deploy codehash" below).
6. **Version.** Bump `VersionMicro` / `VersionModifier` in `params/version.go`.
7. **Verify.** Run the `test-hardfork` skill (and `test-tracereplayverify`
   for full EVM coverage) against an archive node running the new build.

## Invariants (do not break)

- `CodeRecord` slices are **append-only across releases**. Never edit a
  historical entry's hash; rewriting breaks every node syncing from older
  state.
- The overlay reads `PlainState.blockNr - 1` in `core/state/plain_readonly.go`.
  If you touch read paths, preserve that convention.
- Record `BlockNumber` = the fork block (the block the hook executes at,
  i.e. the first block at which the new bytecode is live).
- Don't switch to selfdestruct+recreate to "fix" the overlay — that
  changes the state-root calculation and is a coordinated multi-client
  hardfork, not a node-internal change.

## Recovering deploy codehash

When you need `deployHash` for a pre-PoS row, do not statically decode
init code (`immutable` patches the runtime in the constructor and defeats
static parsers). Run `debug_traceTransaction` with `callTracer` against
an archive node — the top-level `CREATE` call's `output` field is exactly
the bytes stored in `kv.Code`:

```bash
curl -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"debug_traceTransaction",
           "params":["<creation_tx>",{"tracer":"callTracer"}],"id":1}' \
  "$RPC" | jq -r '.result.output' | xxd -r -p | openssl dgst -sha3-256
```

For batch-deploy txs, walk into the trace's sub-calls.
