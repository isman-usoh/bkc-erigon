# Erigon

### ❗❗PLEASE NOTE  ERIGON (BITKUB CHAIN MODIFICATION) IS NOT SUPPORTED AND NOT RECOMMENDED TO USE AS A VALIDATOR NODE ❗❗

Erigon (BITKUB CHAIN MODIFICATION) is a fork of [Erigon](https://github.com/ledgerwatch/erigon) and implementation of Bitkub chain (execution client with light client for consensus layer), on the efficiency
frontier. [Archive Node](https://docs.bitkubchain.org/bitkub-chain-pos/run-archive-node)
by default.

**Disclaimer**: this software is currently a tech preview. We will do our best to keep it stable and make no breaking
changes but we don't guarantee anything. Things can and will break.

**Important defaults**: Erigon is an Archive Node by default (to remove history see: `--prune` flags
in `erigon --help`). We don't allow change this flag after first start.

<code>In-depth links are marked by the microscope sign (🔬) </code>

System Requirements
===================

* For an Archive node of Ethereum Mainnet we recommend >=2TB storage space: 0.8TB state (as of Jan 2024),
  100GB temp files (can symlink or mount folder `<datadir>/temp` to another disk).

SSD or NVMe. Do not recommend HDD - on HDD Erigon will always stay N blocks behind chain tip, but not fall behind.
Bear in mind that SSD performance deteriorates when close to capacity.

RAM: >=16GB, 64-bit architecture.

[Golang version >= 1.19](https://golang.org/doc/install); GCC 10+ or Clang; On Linux: kernel > v4


Usage
=====

### Getting Started

For building the latest stable release (this will be suitable for most users just wanting to run a node):

```sh
git clone --recurse-submodules https://github.com/ledgerwatch/erigon.git
cd erigon
make erigon
./build/bin/erigon
```

Default `--snapshots` for `mainnet`, `goerli`, `gnosis`, `chiado`. Other networks now have default `--snapshots=false`.
Increase
download speed by flag `--torrent.download.rate=20mb`. <code>🔬 See [Downloader docs](./cmd/downloader/readme.md)</code>

Use `--datadir` to choose where to store data.

Use `--chain=bkc-mainnet` for Bitkub Chain Mainnet
and `--chain=bkc-testnet` for Bitkub Chain Testnet.

Running `make help` will list and describe the convenience commands available in the [Makefile](./Makefile).

### Datadir structure

- chaindata: recent blocks, state, recent state history. low-latency disk recommended.
- snapshots: old blocks, old state history. can symlink/mount it to cheaper disk. mostly immutable.
- temp: can grow to ~100gb, but usually empty. can symlink/mount it to cheaper disk.
- txpool: pending transactions. safe to remove.
- nodes:  p2p peers. safe to remove.

### Logging

_Flags:_

- `verbosity`
- `log.console.verbosity` (overriding alias for `verbosity`)
- `log.json`
- `log.console.json` (alias for `log.json`)
- `log.dir.path`
- `log.dir.prefix`
- `log.dir.verbosity`
- `log.dir.json`

In order to log only to the stdout/stderr the `--verbosity` (or `log.console.verbosity`) flag can be used to supply an
int value specifying the highest output log level:

```
  LvlCrit = 0
  LvlError = 1
  LvlWarn = 2
  LvlInfo = 3
  LvlDebug = 4
  LvlTrace = 5
```

To set an output dir for logs to be collected on disk, please set `--log.dir.path` If you want to change the filename prodiced from `erigon` you should also set the `--log.dir.prefix` flag to an alternate name. The flag `--log.dir.verbosity` is
also available to control the verbosity of this logging, with the same int value as above, or the string value e.g. '
debug' or 'info'. Default verbosity is 'debug' (4), for disk logging.

Log format can be set to json by the use of the boolean flags `log.json` or `log.console.json`, or for the disk
output `--log.dir.json`.

### Modularity

Erigon by default is "all in one binary" solution, but it's possible start TxPool as separated processes.
Same true about: JSON RPC layer (RPCDaemon), p2p layer (Sentry), history download layer (Downloader), consensus.
Don't start services as separated processes unless you have clear reason for it: resource limiting, scale, replace by
your own implementation, security.
How to start Erigon's services as separated processes, see in [docker-compose.yml](./docker-compose.yml).

### Testnets

If you would like to give Erigon a try, but do not have spare 2TB on your drive, a good option is to start syncing one
of the public testnets, Görli. It syncs much quicker, and does not take so much disk space:

```sh
git clone --recurse-submodules -j8 https://github.com/ledgerwatch/erigon.git
cd erigon
make erigon
./build/bin/erigon --datadir=<your_datadir> --chain=bkc-testnet
```

Please note the `--datadir` option that allows you to store Erigon files in a non-default location, in this example,
in `goerli` subdirectory of the current directory. Name of the directory `--datadir` does not have to match the name of
the chain in `--chain`.

### Using TOML or YAML Config Files

You can set Erigon flags through a YAML or TOML configuration file with the flag `--config`. The flags set in the
configuration
file can be overwritten by writing the flags directly on Erigon command line

### Example

`./build/bin/erigon --config ./config.yaml --chain=bkc-testnet`

Assuming we have `chain : "bkc-mainnet"` in our configuration file, by adding `--chain=bkc-testnet` allows the overwrite of the
flag inside
of the yaml configuration file and sets the chain to goerli

### TOML

Example of setting up TOML config file

```
`datadir = 'your datadir'
port = 1111
chain = "bkc-mainnet"
http = true
"private.api.addr"="localhost:9090"

"http.api" = ["eth","debug","net"]
```

### YAML

Example of setting up a YAML config file

```
datadir : 'your datadir'
port : 1111
chain : "bkc-mainnet"
http : true
private.api.addr : "localhost:9090"

http.api : ["eth","debug","net"]
```

### Multiple Instances / One Machine

Define 6 flags to avoid conflicts: `--datadir --port --http.port --authrpc.port --torrent.port --private.api.addr`.
Example of multiple chains on the same machine:

```
# mainnet
./build/bin/erigon --datadir="<your_mainnet_data_path>" --chain=mainnet --port=30303 --http.port=8545 --authrpc.port=8551 --torrent.port=42069 --private.api.addr=127.0.0.1:9090 --http --ws --http.api=eth,debug,net,trace,web3,erigon


# sepolia
./build/bin/erigon --datadir="<your_sepolia_data_path>" --chain=sepolia --port=30304 --http.port=8546 --authrpc.port=8552 --torrent.port=42068 --private.api.addr=127.0.0.1:9091 --http --ws --http.api=eth,debug,net,trace,web3,erigon
```

Quote your path if it has spaces.

### Dev Chain

<code> 🔬 Detailed explanation is [DEV_CHAIN](/DEV_CHAIN.md).</code>

Key features
============

<code>🔬 See more
detailed [overview of functionality and current limitations](https://ledgerwatch.github.io/turbo_geth_release.html). It
is being updated on recurring basis.</code>

### More Efficient State Storage

**Flat KV storage.** Erigon uses a key-value database and storing accounts and storage in a simple way.

<code> 🔬 See our detailed DB walkthrough [here](./docs/programmers_guide/db_walkthrough.MD).</code>

**Preprocessing**. For some operations, Erigon uses temporary files to preprocess data before inserting it into the main
DB. That reduces write amplification and DB inserts are orders of magnitude quicker.

<code> 🔬 See our detailed ETL explanation [here](https://github.com/ledgerwatch/erigon-lib/blob/main/etl/README.md).</code>

**Plain state**.

**Single accounts/state trie**. Erigon uses a single Merkle trie for both accounts and the storage.

### Faster Initial Sync

Erigon uses a rearchitected full sync algorithm from
[Go-Ethereum](https://github.com/ethereum/go-ethereum) that is split into
"stages".

<code>🔬 See more detailed explanation in the [Staged Sync Readme](/eth/stagedsync/README.md)</code>

It uses the same network primitives and is compatible with regular go-ethereum nodes that are using full sync, you do
not need any special sync capabilities for Erigon to sync.

When reimagining the full sync, with focus on batching data together and minimize DB overwrites. That makes it possible
to sync Ethereum mainnet in under 2 days if you have a fast enough network connection and an SSD drive.

Examples of stages are:

* Downloading headers;

* Downloading block bodies;

* Recovering senders' addresses;

* Executing blocks;

* Validating root hashes and building intermediate hashes for the state Merkle trie;

* [...]

### JSON-RPC daemon

Most of Erigon's components (txpool, rpcdaemon, snapshots downloader, sentry, ...) can work inside Erigon and as
independent process.

To enable built-in RPC server: `--http` and `--ws` (sharing same port with http)

Run RPCDaemon as separated process: this daemon can use local DB (with running Erigon or on snapshot of a database) or
remote DB (run on another server). <code>🔬 See [RPC-Daemon docs](./cmd/rpcdaemon/README.md)</code>

#### **For remote DB**

This works regardless of whether RPC daemon is on the same computer with Erigon, or on a different one. They use TPC
socket connection to pass data between them. To use this mode, run Erigon in one terminal window

```sh
make erigon
./build/bin/erigon --private.api.addr=localhost:9090 --http=false
make rpcdaemon
./build/bin/rpcdaemon --private.api.addr=localhost:9090 --http.api=eth,erigon,web3,net,debug,trace,txpool
```

#### **gRPC ports**

`9090` erigon, `9091` sentry, `9092` consensus engine, `9093` torrent downloader, `9094` transactions pool

Supported JSON-RPC calls ([eth](./cmd/rpcdaemon/commands/eth_api.go), [debug](./cmd/rpcdaemon/commands/debug_api.go)
, [net](./cmd/rpcdaemon/commands/net_api.go), [web3](./cmd/rpcdaemon/commands/web3_api.go)):

For a details on the implementation status of each
command, [see this table](./cmd/rpcdaemon/README.md#rpc-implementation-status).

### Run all components by docker-compose

Docker allows for building and running Erigon via containers. This alleviates the need for installing build dependencies
onto the host OS.

#### Optional: Setup dedicated user

User UID/GID need to be synchronized between the host OS and container so files are written with correct permission.

You may wish to setup a dedicated user/group on the host OS, in which case the following `make` targets are available.

```sh
# create "erigon" user
make user_linux
# or
make user_macos
```

#### Environment Variables

There is a `.env.example` file in the root of the repo.

* `DOCKER_UID` - The UID of the docker user
* `DOCKER_GID` - The GID of the docker user
* `XDG_DATA_HOME` - The data directory which will be mounted to the docker containers

If not specified, the UID/GID will use the current user.

A good choice for `XDG_DATA_HOME` is to use the `~erigon/.ethereum` directory created by helper
targets `make user_linux` or `make user_macos`.

#### Check: Permissions

In all cases, `XDG_DATA_HOME` (specified or default) must be writeable by the user UID/GID in docker, which will be
determined by the `DOCKER_UID` and `DOCKER_GID` at build time.

If a build or service startup is failing due to permissions, check that all the directories, UID, and GID controlled by
these environment variables are correct.

#### Run

Next command starts: Erigon on port 30303, rpcdaemon on port 8545, prometheus on port 9090, and grafana on port 3000.

```sh
#
# Will mount ~/.local/share/erigon to /home/erigon/.local/share/erigon inside container
#
make docker-compose

#
# or
#
# if you want to use a custom data directory
# or, if you want to use different uid/gid for a dedicated user
#
# To solve this, pass in the uid/gid parameters into the container.
#
# DOCKER_UID: the user id
# DOCKER_GID: the group id
# XDG_DATA_HOME: the data directory (default: ~/.local/share)
#
# Note: /preferred/data/folder must be read/writeable on host OS by user with UID/GID given
#       if you followed above instructions
#
# Note: uid/gid syntax below will automatically use uid/gid of running user so this syntax
#       is intended to be run via the dedicated user setup earlier
#
DOCKER_UID=$(id -u) DOCKER_GID=$(id -g) XDG_DATA_HOME=/preferred/data/folder DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 make docker-compose

#
# if you want to run the docker, but you are not logged in as the $ERIGON_USER
# then you'll need to adjust the syntax above to grab the correct uid/gid
#
# To run the command via another user, use
#
ERIGON_USER=erigon
sudo -u ${ERIGON_USER} DOCKER_UID=$(id -u ${ERIGON_USER}) DOCKER_GID=$(id -g ${ERIGON_USER}) XDG_DATA_HOME=~${ERIGON_USER}/.ethereum DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 make docker-compose
```

Makefile creates the initial directories for erigon, prometheus and grafana. The PID namespace is shared between erigon
and rpcdaemon which is required to open Erigon's DB from another process (RPCDaemon local-mode).
See: https://github.com/ledgerwatch/erigon/pull/2392/files

If your docker installation requires the docker daemon to run as root (which is by default), you will need to prefix
the command above with `sudo`. However, it is sometimes recommended running docker (and therefore its containers) as a
non-root user for security reasons. For more information about how to do this, refer to
[this article](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user).

Windows support for docker-compose is not ready yet. Please help us with .ps1 port.

### Grafana dashboard

`docker compose up prometheus grafana`, [detailed docs](./cmd/prometheus/Readme.md).

###       

old data

Disabled by default. To enable see `./build/bin/erigon --help` for flags `--prune`

Documentation
==============

The `./docs` directory includes a lot of useful but outdated documentation. For code located
in the `./cmd` directory, their respective documentation can be found in `./cmd/*/README.md`.
A more recent collation of developments and happenings in Erigon can be found in the
[Erigon Blog](https://erigon.substack.com/).



FAQ
================

### How much RAM do I need

- Baseline (ext4 SSD): 16Gb RAM sync takes 6 days, 32Gb - 5 days, 64Gb - 4 days
- +1 day on "zfs compression=off". +2 days on "zfs compression=on" (2x compression ratio). +3 days on btrfs.
- -1 day on NVMe

Detailed explanation: [./docs/programmers_guide/db_faq.md](./docs/programmers_guide/db_faq.md)

### Default Ports and Firewalls

#### `erigon` ports

| Port  | Protocol  |        Purpose         | Expose  |
| :---: | :-------: | :--------------------: | :-----: |
| 30303 | TCP & UDP |     eth/66 peering     | Public  |
| 30304 | TCP & UDP |     eth/67 peering     | Public  |
| 9090  |    TCP    |    gRPC Connections    | Private |
| 42069 | TCP & UDP | Snap sync (Bittorrent) | Public  |
| 6060  |    TCP    |    Metrics or Pprof    | Private |
| 8551  |    TCP    | Engine API (JWT auth)  | Private |

Typically, 30303 and 30304 are exposed to the internet to allow incoming peering connections. 9090 is exposed only
internally for rpcdaemon or other connections, (e.g. rpcdaemon -> erigon).
Port 8551 (JWT authenticated) is exposed only internally for [Engine API] JSON-RPC queries from the Consensus Layer
node.

#### `RPC` ports

| Port  | Protocol |           Purpose           | Expose  |
| :---: | :------: | :-------------------------: | :-----: |
| 8545  |   TCP    | HTTP & WebSockets & GraphQL | Private |

Typically, 8545 is exposed only internally for JSON-RPC queries. Both HTTP and WebSocket and GraphQL are on the same
port.

#### `sentry` ports

| Port  | Protocol  |     Purpose      | Expose  |
| :---: | :-------: | :--------------: | :-----: |
| 30303 | TCP & UDP |     Peering      | Public  |
| 9091  |    TCP    | gRPC Connections | Private |

Typically, a sentry process will run one eth/xx protocol (e.g. eth/66) and will be exposed to the internet on 30303.
Port
9091 is for internal gRCP connections (e.g erigon -> sentry).

#### `sentinel` ports

| Port  | Protocol |     Purpose      | Expose  |
| :---: | :------: | :--------------: | :-----: |
| 4000  |   UDP    |     Peering      | Public  |
| 4001  |   TCP    |     Peering      | Public  |
| 7777  |   TCP    | gRPC Connections | Private |

#### Other ports

| Port  | Protocol | Purpose | Expose  |
| :---: | :------: | :-----: | :-----: |
| 6060  |   TCP    |  pprof  | Private |
| 6060  |   TCP    | metrics | Private |

Optional flags can be enabled that enable pprof or metrics (or both) - however, they both run on 6060 by default, so
you'll have to change one if you want to run both at the same time. use `--help` with the binary for more info.

Reserved for future use: **gRPC ports**: `9092` consensus engine, `9093` snapshot downloader, `9094` TxPool

#### Hetzner expecting strict firewall rules

```
0.0.0.0/8             "This" Network             RFC 1122, Section 3.2.1.3
10.0.0.0/8            Private-Use Networks       RFC 1918
100.64.0.0/10         Carrier-Grade NAT (CGN)    RFC 6598, Section 7
127.16.0.0/12         Private-Use Networks       RFC 1918 
169.254.0.0/16        Link Local                 RFC 3927
172.16.0.0/12         Private-Use Networks       RFC 1918
192.0.0.0/24          IETF Protocol Assignments  RFC 5736
192.0.2.0/24          TEST-NET-1                 RFC 5737
192.88.99.0/24        6to4 Relay Anycast         RFC 3068
192.168.0.0/16        Private-Use Networks       RFC 1918
198.18.0.0/15         Network Interconnect
                      Device Benchmark Testing   RFC 2544
198.51.100.0/24       TEST-NET-2                 RFC 5737
203.0.113.0/24        TEST-NET-3                 RFC 5737
224.0.0.0/4           Multicast                  RFC 3171
240.0.0.0/4           Reserved for Future Use    RFC 1112, Section 4
255.255.255.255/32    Limited Broadcast          RFC 919, Section 7
                                                 RFC 922, Section 7
```

Same in [IpTables syntax](https://ethereum.stackexchange.com/questions/6386/how-to-prevent-being-blacklisted-for-running-an-ethereum-client/13068#13068)

### How to get diagnostic for bug report?

- Get stack trace: `kill -SIGUSR1 <pid>`, get trace and stop: `kill -6 <pid>`
- Get CPU profiling: add `--pprof flag`
  run `go tool pprof -png  http://127.0.0.1:6060/debug/pprof/profile\?seconds\=20 > cpu.png`
- Get RAM profiling: add `--pprof flag`
  run `go tool pprof -inuse_space -png  http://127.0.0.1:6060/debug/pprof/heap > mem.png`

### How to run local devnet?

<code> 🔬 Detailed explanation is [here](/DEV_CHAIN.md).</code>

### Docker permissions error

Docker uses user erigon with UID/GID 1000 (for security reasons). You can see this user being created in the Dockerfile.
Can fix by giving a host's user ownership of the folder, where the host's user UID/GID is the same as the docker's user
UID/GID (1000).
More details
in [post](https://www.fullstaq.com/knowledge-hub/blogs/docker-and-the-host-filesystem-owner-matching-problem)

### Run RaspberyPI

https://github.com/mathMakesArt/Erigon-on-RPi-4

Getting in touch
================

### Erigon Discord Server

The main discussions are happening on our Discord server. To get an invite, send an email to `tg [at] torquem.ch` with
your name, occupation, a brief explanation of why you want to join the Discord, and how you heard about Erigon.

### Reporting security issues/concerns

Send an email to `security [at] torquem.ch`.

### Team

Core contributors (in alphabetical order of first names):

* Alex Sharov ([AskAlexSharov](https://twitter.com/AskAlexSharov))

* Alexey Akhunov ([@realLedgerwatch](https://twitter.com/realLedgerwatch))

* Andrea Lanfranchi([@AndreaLanfranchi](https://github.com/AndreaLanfranchi))

* Andrew Ashikhmin ([yperbasis](https://github.com/yperbasis))

* Artem Vorotnikov ([vorot93](https://github.com/vorot93))

* Boris Petrov ([b00ris](https://github.com/b00ris))

* Eugene Danilenko ([JekaMas](https://github.com/JekaMas))

* Igor Mandrigin ([@mandrigin](https://twitter.com/mandrigin))

* Giulio Rebuffo ([Giulio2002](https://github.com/Giulio2002))

* Thomas Jay Rush ([@tjayrush](https://twitter.com/tjayrush))

Thanks to:

* All contributors of Erigon

* All contributors of Go-Ethereum

* Our special respect and gratitude is to the core team of [Go-Ethereum](https://github.com/ethereum/go-ethereum). Keep
  up the great job!

Happy testing! 🥤

Known issues
============

### `htop` shows incorrect memory usage

Erigon's internal DB (MDBX) using `MemoryMap` - when OS does manage all `read, write, cache` operations instead of
Application
([linux](https://linux-kernel-labs.github.io/refs/heads/master/labs/memory_mapping.html)
, [windows](https://docs.microsoft.com/en-us/windows/win32/memory/file-mapping))

`htop` on column `res` shows memory of "App + OS used to hold page cache for given App", but it's not informative,
because if `htop` says that app using 90% of memory you still can run 3 more instances of app on the same machine -
because most of that `90%` is "OS pages cache".
OS automatically frees this cache any time it needs memory. Smaller "page cache size" may not impact performance of
Erigon at all.

Next tools show correct memory usage of Erigon:

- `vmmap -summary PID | grep -i "Physical footprint"`. Without `grep` you can see details
    - `section MALLOC ZONE column Resident Size` shows App memory usage, `section REGION TYPE column Resident Size`
      shows OS pages cache size.
- `Prometheus` dashboard shows memory of Go app without OS pages cache (`make prometheus`, open in
  browser `localhost:3000`, credentials `admin/admin`)
- `cat /proc/<PID>/smaps`

Erigon uses ~4Gb of RAM during genesis sync and ~1Gb during normal work. OS pages cache can utilize unlimited amount of
memory.

**Warning:** Multiple instances of Erigon on same machine will touch Disk concurrently, it impacts performance - one of
main Erigon optimisations: "reduce Disk random access".
"Blocks Execution stage" still does many random reads - this is reason why it's slowest stage. We do not recommend
running
multiple genesis syncs on same Disk. If genesis sync passed, then it's fine to run multiple Erigon instances on same
Disk.

### Blocks Execution is slow on cloud-network-drives

Please read https://github.com/ledgerwatch/erigon/issues/1516#issuecomment-811958891
In short: network-disks are bad for blocks execution - because blocks execution reading data from db non-parallel
non-batched way.

### Filesystem's background features are expensive

For example: btrfs's autodefrag option - may increase write IO 100x times

### Gnome Tracker can kill Erigon

[Gnome Tracker](https://wiki.gnome.org/Projects/Tracker) - detecting miners and kill them.

### the --mount option requires BuildKit error

For anyone else that was getting the BuildKit error when trying to start Erigon the old way you can use the below...

```
XDG_DATA_HOME=/preferred/data/folder DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 make docker-compose
```
