# bitmessage

[![CI](https://github.com/teruteru128/bitmessage/actions/workflows/ci.yml/badge.svg)](https://github.com/teruteru128/bitmessage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

English | [日本語](README-ja.md)

A from-scratch implementation of the Bitmessage P2P messaging protocol in C.

Aiming to interoperate with [PyBitmessage](https://github.com/Bitmessage/PyBitmessage) over the real network,
it implements the crypto layer (ECIES/ECDSA), PoW, every object wire format, the P2P network layer,
a JSON-RPC API and a CLI from the ground up.

The design (architecture, current backlog) is in [DESIGN.md](DESIGN.md), the dated development history
(how bugs were found, how discussions concluded, etc.) in [DESIGN-LOG.md](DESIGN-LOG.md), and the
changes in each release in [CHANGELOG.md](CHANGELOG.md). These documents are written in Japanese.

## Status

The latest release is v1.4.0 (2026-11-05). The following is implemented and has been confirmed to work
on the real network, except for the experimental post-quantum extension described below.

### Protocol and cryptography

- **Key lifecycle**: address generation (v3/v4), private keys stored encrypted with a passphrase-derived
  KEK, unlock/lock/delete
- **Crypto layer**: ECIES encryption and ECDSA signatures (SHA256). Verified to match PyBitmessage
  (pyelliptic/highlevelcrypto) byte for byte
- **Building and parsing every object wire format**: `getpubkey` / `pubkey` (v2/v3/v4) / `msg` /
  `broadcast` / `ack` / `onionpeer`
- **PoW engine**: multithreaded parallel search (one thread per CPU). The PoW of received objects is
  checked too, and objects below the network's minimum difficulty are rejected on arrival

### Messaging

- **Direct messages**: PoW on send, acks, automatic getpubkey requests and replies, automatic resend
  when no ack arrives (with doubling intervals). The recipient's public key is always resolved through
  `pubkey_cache` (it can be registered in advance with `cachePubkey`; passing it directly to
  `sendMessage` was removed to prevent encrypting with a wrong key and polluting the cache)
- **Broadcast subscription and sending**: broadcasts from subscribed addresses are decrypted into the
  inbox automatically; send with `sendBroadcast`
- **Chans (private group channels)**: everyone derives the same address and keys from a shared
  passphrase (`joinChan`), posts by sending a message to the chan itself, and other members decrypt it
  automatically with trial decryption
- **Inbox and sent box**: `getInboxMessages`/`getSentMessages`, `trashMessage` (soft delete)
- **Address book**: add, delete, list (duplicates are rejected, as in PyBitmessage)
- **Long messages**: `--body-file` reads the body from a file or stdin (so the body does not show up in
  `ps` or the shell history). subject + body may be up to 261,644 bytes, the same as PyBitmessage

### Key migration and large-scale use

- **Migrating from PyBitmessage**: bulk import of `keys.dat` (`import-keys-dat`), per-address
  import/export of WIF key pairs, chan settings from `keys.dat` preserved, repair of garbled labels
  (`fix-labels-from-keys-dat`)
- **Bulk unlock**: a two-stage KDF (the vault scheme, DESIGN.md section 7.4) unlocks thousands of
  addresses with a single key derivation. `unlock-all` (every row of identity.db, up to 10,000) and
  `unlock-addresses` (only the addresses listed in a file). The more addresses are unlocked, the
  heavier trial decryption of incoming msgs becomes, so if you hold many addresses, unlock only the
  ones you need with `unlock-addresses`
- **v3-to-v4 migration**: move a v3 address to the v4 address with the same keys (`convert-to-v4` /
  `convert-all-v3-to-v4`)

### Network

- **P2P network layer**: handshake and wiring of version/verack/addr/inv/getdata/object. Keeps
  connections up and reconnects, relays received objects to other peers, and sends the list of held
  objects to new peers. Peers are chosen by rating-weighted random sampling, as in PyBitmessage
- **Inbound connections**: listening on TCP (`BM_INBOUND_PORT`). Supports automatic creation of a hidden
  service through the Tor ControlPort (`BM_TOR_CONTROL=1`) or a static torrc setup
  (`BM_ONION_ADDRESS`). With idle/handshake timeouts, keepalive, and rate limits on concurrent
  connections and accepts
- **Dandelion++**: the stem/fluff state machine, advertising the `NODE_DANDELION` service bit
- **Onion peers**: receives PyBitmessage-compatible `onionpeer` objects and records v3 onion peers in
  `peers.db`, and periodically announces its own onion address
- **Outbound SOCKS5 proxy**: the setting for using Tor etc. for outbound connections is stored in
  `config.db`. The setting for onion peers (`.onion`, `set-socks-proxy-onion`) and the one for clearnet
  IPs (`set-socks-proxy-clearnet`, disabled = direct by default) are separate, so enabling only the
  onion one keeps clearnet connections direct (matching PyBitmessage's split between socksproxytype
  and onionsocksproxytype; see DESIGN.md section 11). Changes take effect at the next reconnect cycle
  (within 30 seconds by default) without restarting the daemon
- **Manually added peers and observed node list**: add a node you have personally confirmed to exist with
  `addPeer`. In addition, `seeds/observed_nodes.txt` (a separate file that states its origin and
  limits, apart from the official seeds) is shipped as a foothold for making the first connection on a
  fresh install even if all mainnet seeds are down
- **Defenses**: filtering of private/loopback/link-local etc. addresses learned from `addr`, throttling
  of getpubkey replies, checking the declared length of P2P messages before the data arrives
  (disconnecting peers that declare huge values), preventing connections to itself

### Operation

- **JSON-RPC 2.0 API + CLI**: everything above can be operated from `bitmessage-cli`. CLI messages are
  shown in Japanese under a Japanese locale and in English otherwise (gettext). Daemon logs are in
  English
- **Logging**: eight log levels (`BM_LOG_LEVEL`). Under systemd, timestamps are left to journald
- **Installation**: `cmake --install`, systemd unit file (`systemd/bitmessaged.service`)

### Experimental: post-quantum extension (v5 addresses)

A proposed address and object format using ML-DSA/ML-KEM together with Ed25519/X25519, implemented in
`src/pq/` and the daemon. It needs a build with OpenSSL 3.5 or later and is off unless you enable it
(`[pq] enabled = 1`, or `BM_PQ_ENABLED=1`). Other nodes relay v5 objects without understanding them, so
only nodes that enable it can read them.

- This is a proposal, not part of the Bitmessage protocol: PyBitmessage and other clients cannot use v5
  addresses. A v5 address can only exchange messages with another v5 address.
- Objects are about 7.4 KB larger than v4, so PoW takes longer: expect a few times longer per message, and
  on the order of half a minute on 16 cores to answer a getpubkey request.
- Not available for v5: random address generation, chans, and `export-address`.
- Not yet used on the real network. Two-way messaging and relaying through nodes that do not understand v5
  (including PyBitmessage) were tested on an isolated network.

See [DESIGN-PQ.md](DESIGN-PQ.md) for details.

### Out of scope (known limitations, backlog)

- GPU/OpenCL PoW — explicitly ruled out of the v1 scope in section 8; still deferred
- Peer discovery by UDP broadcast on the LAN — deferred for now since manually adding peers covers it
  (frozen)
- Migrating the EC_KEY/ECDSA code in `core/crypto.c` to the EVP_PKEY-based API — deferred until
  OpenSSL actually announces the removal of the deprecated API (frozen)

See [DESIGN.md section 11](DESIGN.md#11-次にやること引き継ぎメモ随時更新) for details.

## Building

### Dependencies

- CMake 3.25 or later, Ninja (or another build system supported by CMake)
- A C compiler (GCC/Clang, C11)
- OpenSSL, SQLite3, pthread
  (the post-quantum prototype `src/pq` is built only with OpenSSL 3.5 or later. With older versions it
  is excluded automatically, with no effect on the daemon. DESIGN-PQ.md section 6.1)
- libmicrohttpd, cJSON (HTTP transport and JSON handling for the JSON-RPC API server, detected through
  `pkg-config`. See DESIGN.md section 6.3)
- gettext (optional; builds the Japanese translation of `bitmessage-cli` messages. Without it the CLI
  runs in English only. DESIGN.md section 11, item 54)

On Debian/Ubuntu:

```sh
sudo apt install cmake ninja-build build-essential pkg-config \
                 libssl-dev libsqlite3-dev libmicrohttpd-dev libcjson-dev gettext
```

```sh
cmake -B build-Debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
ninja -C build-Debug
```

## Testing

```sh
ctest --test-dir build-Debug --output-on-failure
```

## Usage

When the daemon (`bitmessaged`) starts, it prints the JSON-RPC API credentials (the user name is always
`bitmessage`; the password is generated randomly at each start) to standard error. They are
intentionally not persisted; the credentials are the one thing that cannot be set in the config file.

Startup settings go in `bitmessage.conf` (INI format, placed in the current directory of `bitmessaged`;
without it the daemon starts with defaults). Copying `bitmessage.conf.example` is the quickest way to
start. Every item can also be set with an environment variable, which takes precedence over the file
(precedence: environment variable > `bitmessage.conf` > default).

```sh
cp bitmessage.conf.example bitmessage.conf
# Edit only what you need (testnet, API port, Tor hidden service integration, etc.)

# Environment variables override settings for a single run. For example, the default is mainnet;
# set BM_TESTNET=1 to connect to testnet.
# The JSON-RPC API listens on port 8442 by default. Change it with BM_API_PORT if it clashes with
# another process (bitmessage-cli reads the same variable, so set it there too)
./build-Debug/src/bitmessaged
```

### Environment variables

For `bitmessaged` (overrides the value in `bitmessage.conf` for this run; precedence: environment
variable > `bitmessage.conf` > default):

| Variable | Default | Description |
| --- | --- | --- |
| `BM_CONFIG_FILE` | `bitmessage.conf` | Location of the startup config file |
| `BM_DATA_DIR` | `.` (CWD) | Where the DB files (five of them, such as `peers.db`) live. For fixed-path setups under systemd etc. (e.g. `/var/lib/bitmessage`) |
| `BM_SEEDS_FILE` | `seeds/observed_nodes.txt` | Location of the list of "nodes of unknown identity confirmed by the developer" (section 11; mainnet only; startup works without it) |
| `BM_TESTNET` | (mainnet) | `1` switches to testnet |
| `BM_NO_CONNECT` | (connect) | `1` makes no P2P connections at all (mainly for tests) |
| `BM_MAX_OUTBOUND` | `3` | Maximum number of concurrent outbound connections |
| `BM_PQ_ENABLED` | (disabled) | `1` enables the experimental post-quantum extension (v5 addresses). Requires a build with OpenSSL 3.5 or later |
| `BM_API_PORT` | `8442` | Listen port of the JSON-RPC API |
| `BM_INBOUND_PORT` | (disabled) | Port accepting inbound connections from a Tor hidden service etc. Disabled when 0 or unset |
| `BM_DEFAULT_NONCE_TRIALS_PER_BYTE` | `1000` | Default PoW difficulty for new addresses (nonce trials per byte) |
| `BM_DEFAULT_PAYLOAD_LENGTH_EXTRA_BYTES` | `1000` | Same (payload length extra bytes) |
| `BM_TOR_CONTROL` | (disabled) | `1` tries to create a hidden service automatically through the Tor ControlPort (requires `BM_INBOUND_PORT`. Under systemd, the service needs group permission to access Tor's ControlPort socket; see the systemd section below) |
| `BM_TOR_CONTROL_SOCKET` | `/run/tor/control` | Path of the ControlPort Unix domain socket (the default of the Debian/Ubuntu tor package. It may differ on Fedora/Arch etc., so set the actual path when using `BM_TOR_CONTROL=1` on other distributions) |
| `BM_TOR_CONTROL_HOST` | `127.0.0.1` | TCP fallback host when the socket above cannot be reached |
| `BM_TOR_CONTROL_PORT` | `9051` | Same, port |
| `BM_TOR_VIRTUAL_PORT` | `8444` | Port other peers use to connect to your onion address |
| `BM_ONION_ADDRESS` | (unset) | With a static torrc setup, your onion address given directly (takes precedence over `BM_TOR_CONTROL`) |
| `BM_LOG_LEVEL` | `INFO` | Minimum log level to print. From most to least verbose: `DEBUG3`/`DEBUG2`/`DEBUG1`/`DEBUG`/`INFO`/`NOTICE`/`WARN`/`ERROR` (case-insensitive) |
| `BM_LOG_TIMESTAMPS` | (auto) | `1`/`0` turns timestamps at the start of log lines on/off. When unset, they are omitted under systemd (journald) and added otherwise |

For `bitmessage-cli`:

| Variable | Default | Description |
| --- | --- | --- |
| `BM_API_HOST` | `127.0.0.1` | Host of the daemon to connect to |
| `BM_API_PORT` | `8442` | Port of the daemon (match the daemon's setting) |
| `BM_API_USER` | (required) | JSON-RPC API user name (as printed by the daemon at startup) |
| `BM_API_PASS` | (required) | Its password |
| `BM_LOCALEDIR` | (auto) | Directory to look for message translations (.mo) in. When unset, `locale/` next to the executable (build tree), otherwise the install location (`/usr/local/share/locale` by default) |

The display language follows the usual locale settings (`LANG`/`LC_MESSAGES`/`LC_ALL`/`LANGUAGE`).
To get English in a Japanese environment, set e.g. `LC_MESSAGES=C`.

### Running as a systemd service (`systemd/bitmessaged.service`)

After `cmake --install`, the installed `.service` file uses `DynamicUser=yes` to create a dedicated
service user automatically. When connecting to the Tor ControlPort Unix domain socket with
`BM_TOR_CONTROL=1` (`/run/tor/control` by default, owned by the `debian-tor` group in the Debian/Ubuntu
tor package), the user created by `DynamicUser` belongs to no group by default, so the unit file must
add it to the group with `SupplementaryGroups=debian-tor` (the shipped `.service` file already does).
If the group owning Tor's ControlPort socket differs on your distribution, replace it with the actual
group name. It is not needed if you do not use `BM_TOR_CONTROL` (SOCKS5 outbound only, or no Tor at
all), but leaving it in does no harm.

The `.service` file waits for Tor with `After=tor.service`/`Wants=tor.service` (a soft dependency: if
`tor.service` is disabled or not installed, the daemon still starts).

### Using the CLI

Operate the daemon with `bitmessage-cli` from another terminal (set `BM_API_USER`/`BM_API_PASS` to what
the daemon printed at startup).

```sh
export BM_API_USER=bitmessage
export BM_API_PASS=<password printed by the daemon at startup>

CLI=./build-Debug/src/cli/bitmessage-cli

# Create and unlock an address
$CLI create-address "my passphrase" 4 1 1 "label" "store passphrase"
$CLI unlock BM-xxxxxxxx "store passphrase"
$CLI list-addresses

# With BM_PQ_ENABLED=1, version 5 creates a post-quantum address (see "Experimental" above)
$CLI create-address "my passphrase" 5 1 1 "label" "store passphrase"

# Sending to someone whose public key you don't have yet sends a getpubkey request automatically
# (that send fails; send again once the pubkey has arrived)
$CLI send-message BM-fromAddress BM-toAddress "subject" "body" 3600 1
$CLI get-inbox
$CLI get-sent

# For long or multi-line bodies, read the body from a file with --body-file ("-" for stdin).
# A body passed as an argument is visible to other users via ps(1) and stays in the shell history
$CLI send-message --body-file ./body.txt BM-fromAddress BM-toAddress "subject" 3600 1
$CLI send-message --body-file - BM-fromAddress BM-toAddress "subject" < ./body.txt

# Subscribe to and send broadcasts
$CLI add-subscription BM-someAddress "label"
$CLI send-broadcast BM-fromAddress "subject" "body" 3600
$CLI send-broadcast --body-file ./body.txt BM-fromAddress "subject" 3600

# Chans (private group channels): everyone using the same passphrase shares the same address and keys
CHAN=$($CLI join-chan "my chan passphrase" "my chan" "store passphrase" | tr -d '"')
$CLI unlock "$CHAN" "store passphrase"
$CLI send-message "$CHAN" "$CHAN" "subject" "body" 3600 1

# Bulk-import PyBitmessage's keys.dat, then unlock only the addresses you need
# (addresses.txt has one address per line; "-" reads from stdin)
$CLI import-keys-dat ~/.config/PyBitmessage/keys.dat "store passphrase"
$CLI unlock-addresses ./addresses.txt "store passphrase"

# Route outbound connections to onion peers (.onion) through a SOCKS5 proxy (Tor etc.). Clearnet IPs
# stay direct (disabled) by default. Takes effect at the next reconnect cycle (within 30 seconds by
# default) without restarting the daemon
$CLI set-socks-proxy-onion 1 127.0.0.1 9050
$CLI get-socks-proxy-onion
# Enable this only if you also want to anonymize clearnet connections (they go through Tor exit nodes,
# which can hurt connectivity to other nodes; see "Outbound SOCKS5 proxy" above)
$CLI set-socks-proxy-clearnet 1 127.0.0.1 9050
$CLI get-socks-proxy-clearnet

# Manually add a node you have personally confirmed to exist (a last resort when all mainnet seeds are down)
$CLI add-peer 203.0.113.1 8444

# Others
$CLI cache-pubkey BM-address <signingPubkeyHex> <encryptionPubkeyHex>
$CLI list-subscriptions
$CLI list-connections
$CLI lock BM-address
$CLI delete BM-address
```

`bitmessage-cli --help` (or running it without arguments) lists every command.

## Directory layout

```
src/
  common/   Shared utilities (varint, hash, JSON, queues, logging, etc.)
  core/     Key management, crypto, building/parsing objects, send/receive pipeline, peer management, JSON-RPC API
  infra/    P2P network layer (connection management, object sync, Dandelion++, Tor integration)
  pow/      PoW engine
  cli/      CLI client
  pq/       Post-quantum extension (v5 addresses and objects)
po/         Translations of bitmessage-cli messages (gettext)
tests/      ctest-based test suite
seeds/      Fallback node list for when all mainnet seeds are down (observed_nodes.txt)
systemd/    systemd unit file
DESIGN.md       Design document (overall design, implementation status and decisions, backlog)
DESIGN-LOG.md   Dated development history
DESIGN-PQ.md    Post-quantum extension proposal
CHANGELOG.md    Changes in each release
```

## Contact

Bitmessage: `BM-2cUcXwGMhcqfbbjrGE1Cxb92SBdQerarL6`

Release announcements on Bitmessage are sent from this address. An announcement from any other address is not
from this project.
