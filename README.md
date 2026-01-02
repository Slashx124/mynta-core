# Mynta Core

Mynta Core is the reference implementation of the Mynta blockchain. It provides the full node daemon, consensus logic, and networking stack that power the Mynta network.

## What is Mynta?

Mynta is an independent, community-driven cryptocurrency focused on transparency, reliability, and long-term sustainability. The project emphasizes correctness over features, reproducibility over convenience, and open development from day one.

Mynta operates as a decentralized peer-to-peer network with no central authority. Transaction processing, block validation, and consensus are carried out collectively by network participants running Mynta Core.

### Design Principles

- **Clean launch**: No pre-mine, no hidden allocations, no privileged infrastructure
- **Reproducible builds**: Deterministic compilation ensures binary integrity
- **Correctness first**: Security and consensus safety take priority over feature velocity
- **Open development**: All changes are proposed, reviewed, and merged in public

## Features

- **Full node implementation**: Complete blockchain validation and relay
- **Integrated wallet**: Send, receive, and manage funds directly from the daemon
- **Asset layer**: Create and transfer user-defined assets on-chain
- **KawPoW consensus**: ASIC-resistant proof-of-work active from block height 1
- **Standard RPC interface**: JSON-RPC API for application integration
- **Cross-platform**: Builds on Linux, macOS, and Windows

## Getting Started

### Prerequisites

Mynta Core requires standard build tools and libraries. See [BUILDING.md](BUILDING.md) for detailed platform-specific instructions.

Minimum requirements:
- C++14 compatible compiler (GCC 7+, Clang 8+, MSVC 2017+)
- GNU Autotools (autoconf, automake, libtool)
- Boost 1.64+
- OpenSSL 1.1+
- libevent 2.1+
- Berkeley DB 4.8 (for wallet support)

### Build

```bash
./autogen.sh
./configure
make
make install  # optional
```

### Run

```bash
# Start the daemon
myntad

# Interact via CLI
mynta-cli getblockchaininfo
mynta-cli help
```

Default data directory:
- Linux: `~/.mynta`
- macOS: `~/Library/Application Support/Mynta`
- Windows: `%APPDATA%\Mynta`

Default configuration file: `mynta.conf`

### Network Ports

| Network  | P2P Port | RPC Port |
|----------|----------|----------|
| Mainnet  | 8770     | 8766     |
| Testnet  | 18770    | 18766    |
| Regtest  | 18444    | 18443    |

## Documentation

- [BUILDING.md](BUILDING.md) — Build instructions for all platforms
- [doc/](doc/) — Additional documentation and specifications
- [contrib/](contrib/) — Helper scripts and configuration examples

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Reporting issues
- Submitting pull requests
- Code review expectations
- Consensus-critical change process

## Testing

```bash
# Unit tests
make check

# Functional tests (requires Python 3)
test/functional/test_runner.py
```

See [src/test/README.md](src/test/README.md) for details on the test framework.

## License

Mynta Core is released under the MIT License. See [COPYING](COPYING) for the full license text.

## Security

If you discover a security vulnerability, please report it responsibly. Do not open a public issue. Contact the maintainers directly or use any published security contact method.
