---
name: test-tracereplayverify
description: End-to-end EVM-execution check that exercises the system-contract overlay by replaying historical blocks through trace_replayBlockTransactions.
---

# Verifying system-contract hardforks (EVM-execution level)

Use this skill when the user asks to "run the trace replay test", "do the
deeper hardfork check", or after `test-hardfork` passes and you want to
confirm the overlay actually feeds the EVM correctly during system calls.

`hardforkverify` only checks `eth_getCode`. This tool replays whole
historical blocks through `trace_replayBlockTransactions`, which forces
the EVM to execute the synthetic `commitSpan` system tx using whatever
bytecode the overlay returns. A broken overlay panics here
(index-out-of-range) where `eth_getCode` would silently return wrong bytes.

## Run it

```bash
go run ./cmd/tracereplayverify --rpc=http://NODE:8545 --chain=mainnet
go run ./cmd/tracereplayverify --rpc=http://NODE:8545 --chain=testnet
# Optional flags:
#   --trace-type=trace,vmTrace,stateDiff   request multiple trace types
#   --insecure                             skip TLS cert verification
#   --timeout=60s                          per-request timeout
```

## What blocks get tested

Derived programmatically from `SystemContractCodeLookup`:

1. **Boundary triplets** `F-1, F, F+1` for every CodeRecord fork block of
   every kub system contract.
2. **Span-commit straddles** — the nearest mid-span (`N % 50 == 26`)
   block before and after each unique fork block. That's where
   `BKCValidatorSet.commitSpan` is actually invoked under the contract
   version in force.
3. **Two control blocks** far from any fork to confirm normal-path replay.

## Pass criterion

Every block returns a non-error JSON-RPC response. Any `FAIL` row is a
real bug — typically:

- Index-out-of-range panic from the EVM running the wrong (post-fork)
  bytecode against pre-fork state. Look at the overlay path in
  `core/state/plain_readonly.go` and the records in
  `core/systemcontracts/kub_upgrades.go`.
- Missing pre-PoS record causing fallback to latest bytecode at boundary
  blocks.

## When to use

- **Always after** `test-hardfork` passes when shipping a new SetCode
  hardfork — `eth_getCode` correctness is necessary but not sufficient.
- After any change to `core/state/plain_readonly.go` or
  `core/state/historyv2read/`.
- Before tagging a release that touches the historical-read path.

## Limitations

- Needs an **archive** node with `trace_*` namespace enabled.
- Slower than `hardforkverify` because each block triggers a full block
  replay on the node.
