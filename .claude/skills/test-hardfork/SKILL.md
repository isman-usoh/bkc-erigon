---
name: test-hardfork
description: Verify that an archive RPC returns the historically-correct bytecode for every Bitkub system contract at every CodeRecord boundary using cmd/hardforkverify.
---

# Verifying system-contract hardforks (eth_getCode level)

Use this skill when the user asks to "verify the hardfork", "test the
hardforked node", "check the system contracts", or after deploying a new
build that bumps `core/systemcontracts/kub_upgrades.go`.

## Run it

```bash
go run ./cmd/hardforkverify --rpc=http://NODE:8545 --chain=mainnet
go run ./cmd/hardforkverify --rpc=http://NODE:8545 --chain=testnet

# Cross-check two nodes (e.g. fixed vs unfixed):
go run ./cmd/hardforkverify --rpc=URL_A --rpc-compare=URL_B --chain=mainnet

# Other useful flags
--latest-only          only check the latest record per contract
--contract=StakeManager  filter to one contract
--json                 machine-readable output
--insecure             skip TLS cert verification
```

`--chain` and `--rpc` are required. The tool reads
`core/systemcontracts.SystemContractCodeLookup` so the build of the tool
must include the records you're verifying.

## What it checks (per record `r` in each contract's slice)

| label | block | must pass? |
|---|---|---|
| `latest` | `latest` | yes — must equal last record's hash |
| `at-fork` | `r.BlockNumber` | yes |
| `after` | `r.BlockNumber + 1` | yes |
| `before` | `r.BlockNumber - 1` | yes (must equal previous record) |
| `mid-span` | midpoint between previous and current record | yes |
| `pre-first-record` | `firstRecord.BlockNumber - 1` | informational only |

Pass criterion: every contract reports `N/N` critical and an
`HARDFORKED` verdict in the SUMMARY block.

## Reading failures

- **`FAIL` rows on `before`/`mid-span`** — overlay off-by-one. Check
  `core/state/plain_readonly.go:195-198` (`overlayBlock = blockNr - 1`).
- **`FAIL` row returns empty (`-`)** — the expected `CodeHash` is not in
  `kv.Code` on that node. Either the records list has the wrong hash
  (re-derive via `debug_traceTransaction`, see `setcode-hardfork` skill)
  or the node was synced before the new bytecode was deployed.
- **`pre-first-record` empty** — correct when the contract did not exist
  at `deployBlock - 1`. Reported as `·` and does not gate verdict; keep
  it because it surfaces overlay regressions for free.
- **Cross-node `DIFF`** — if `mustPass: false`, it's an informational
  divergence; if `mustPass: true`, one node is wrong.

## Limitations

- Tests `eth_getCode` only. A correct codehash here does not prove the
  EVM actually runs the right code during a system call. Run
  `test-tracereplayverify` for the EVM-execution-level check.
- Needs an **archive** node. Pruned nodes will return errors on old blocks.
