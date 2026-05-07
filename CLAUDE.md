# CLAUDE.md — Bitkub erigon fork

This is a Bitkub fork of erigon (V2). The kub-specific surface area beyond
upstream erigon is concentrated in:

- `consensus/clique/` — Bitkub's PoA consensus, including hardfork hooks
  (`hardfork/lausanne/`, `hardfork/basel/`, ...) wired from
  `clique.go::Finalize`.
- `core/systemcontracts/` — system-contract addresses (`const.go`),
  per-chain CodeRecord overlay (`kub_upgrades.go`), and the upstream
  upgrade machinery (`upgrade.go`).
- `core/state/plain_readonly.go` — the historical-read path. Contains the
  `systemContractLookup` overlay used to compensate for erigon V2's
  changeset writer stripping codehash from BEFORE records.
- `cmd/hardforkverify/` — `eth_getCode`-level verifier for system-contract
  hardforks.
- `cmd/tracereplayverify/` — EVM-execution-level verifier (replays blocks
  through `trace_replayBlockTransactions`).
- `params/version.go` — `VersionMajor.Minor.Micro-Modifier` per release.

## Hardforks: quick recap

Bitkub hardforks that change system-contract behavior call
`state.SetCode(addr, newBytecode)` directly during `clique.Finalize`. This
does **not** bump incarnation, so:

1. `kv.PlainContractCode[(addr, incarnation)]` is overwritten in place —
   the old codehash is unrecoverable from this table.
2. The changeset writer strips codehash from the BEFORE record by design
   (`omitHashes=true`).

To get correct historical `eth_getCode` results, every system contract has
an overlay entry in `core/systemcontracts.SystemContractCodeLookup` —
a list of `{BlockNumber, CodeHash}` checkpoints. Records are append-only
across releases.

The overlay reads `PlainState.blockNr - 1` because `PlainState.blockNr =
N+1` means "state at end of block N" (the read-side dual of the
changeset's block-of-application keying). Off-by-one bugs at fork
boundaries are almost always a missed subtraction in this path.

`docs/hardfork/setcode.md` is the long version of this story.

## Skills

When the user asks to do one of these things, use the matching skill:

- **Adding a new hardfork** → `.claude/skills/setcode-hardfork/`
- **Verifying the hardfork via eth_getCode** → `.claude/skills/test-hardfork/`
- **Verifying the hardfork via trace_replayBlockTransactions** →
  `.claude/skills/test-tracereplayverify/`

Quick commands:

```bash
# eth_getCode-level verification (run after every release)
go run ./cmd/hardforkverify --rpc=http://NODE:8545 --chain=mainnet

# EVM-execution-level verification (deeper, mainnet only today)
go run ./cmd/tracereplayverify --rpc=http://NODE:8545
```

## Invariants and tripwires

- **`CodeRecord` slices in `kub_upgrades.go` are append-only.** Editing a
  historical entry's hash breaks every node syncing from before the
  change.
- **Pre-PoS row.** The first record per contract should be the original
  deploy block + deploy codehash. Without it, reads in `[deployBlock,
  firstHardfork-1]` fall through to the broken `kv.PlainContractCode`
  path. To recover a deploy codehash, use `debug_traceTransaction` with
  `callTracer` — static init-code parsers fail because Solidity
  `immutable` patches the runtime in the constructor.
- **`PlainState.blockNr` semantics.** `blockNr = N+1` ⇒ "state at end of
  block N". The overlay uses `blockNr - 1`. Preserve this convention in
  any new historical-read path.
- **Don't switch SetCode hardforks to selfdestruct+recreate.** It would
  remove the need for the overlay but changes state-root calculation —
  that's a coordinated multi-client hardfork, not an internal change.
- **HistoryV3 is the long-term fix.** Upstream erigon3 preserves codehash
  per-block-per-address natively; once we migrate, the overlay can be
  deleted. Tracked separately.

## Release flow for system-contract changes

1. Write the hardfork instruction (`consensus/clique/hardfork/<name>/`).
2. Wire it in `consensus/clique/clique.go::Finalize`.
3. Append `{BlockNumber, CodeHash}` records in
   `core/systemcontracts/kub_upgrades.go` for both mainnet and testnet
   (and a pre-PoS row if the contract is new to the overlay).
4. Bump `params/version.go`.
5. Build, deploy to an archive node, run `hardforkverify` then
   `tracereplayverify` (mainnet).
