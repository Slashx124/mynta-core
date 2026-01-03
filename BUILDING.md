# Building Mynta Core

This document describes how to build Mynta Core (myntad, mynta-cli, mynta-qt) from source on Linux.

## Supported Platforms

- Debian 12 (Bookworm)
- Ubuntu 22.04 LTS (Jammy)
- Ubuntu 24.04 LTS (Noble)
- Windows 10/11 via WSL2 (Ubuntu)

## Dependencies

### Debian/Ubuntu

```bash
# Install base development tools
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libtool \
    autotools-dev \
    automake \
    pkg-config \
    bsdmainutils \
    python3 \
    git \
    dos2unix

# Install required libraries
sudo apt-get install -y \
    libssl-dev \
    libevent-dev \
    libboost-system-dev \
    libboost-filesystem-dev \
    libboost-chrono-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libboost-program-options-dev

# Optional: BerkeleyDB 4.8 for wallet support
# Note: You can use --with-incompatible-bdb if BDB 4.8 is not available
sudo apt-get install -y libdb4.8-dev libdb4.8++-dev 2>/dev/null || \
    sudo apt-get install -y libdb-dev libdb++-dev

# Optional: MiniUPnP for UPnP support
sudo apt-get install -y libminiupnpc-dev

# Optional: ZeroMQ for ZMQ notifications
sudo apt-get install -y libzmq3-dev

# Optional: Qt5 for GUI
sudo apt-get install -y \
    libqt5gui5 \
    libqt5core5a \
    libqt5dbus5 \
    qttools5-dev \
    qttools5-dev-tools \
    libprotobuf-dev \
    protobuf-compiler \
    libqrencode-dev
```

## Building

### Clone Repository

```bash
git clone https://github.com/Slashx124/mynta-core.git
cd mynta-core

# Initialize submodules (required for BLS library)
git submodule update --init --recursive
```

### Build the BLS Library

The BLST library must be built before the main project:

```bash
cd src/bls/blst
./build.sh
cd ../../..
```

### Build Steps

```bash
# Fix line endings if building on Windows/WSL
dos2unix autogen.sh configure.ac Makefile.am

# Generate build scripts
./autogen.sh

# Configure (adjust options as needed)
./configure \
    --disable-bench \
    --disable-tests \
    --with-incompatible-bdb \
    --without-gui

# Build (use number of CPU cores)
make -j$(nproc)

# Optional: Install
sudo make install
```

### Configure Options

| Option | Description |
|--------|-------------|
| `--with-incompatible-bdb` | Allow BerkeleyDB versions other than 4.8 |
| `--disable-wallet` | Build without wallet support |
| `--without-gui` | Build without Qt GUI |
| `--without-miniupnpc` | Build without UPnP support |
| `--disable-tests` | Don't build unit tests |
| `--disable-bench` | Don't build benchmarks |
| `--enable-debug` | Build with debug symbols |

### Build Qt GUI

To build the graphical wallet:

```bash
./configure --with-gui=qt5 --with-incompatible-bdb
make -j$(nproc)
```

## Binaries

After a successful build, the following binaries are available in `src/`:

| Binary | Description |
|--------|-------------|
| `myntad` | Mynta daemon |
| `mynta-cli` | Command-line RPC client |
| `mynta-tx` | Transaction utility (if built with --with-tx) |
| `mynta-qt` | Qt GUI wallet (if built with Qt) |

## Running

### First Run

```bash
# Create data directory
mkdir -p ~/.mynta

# Create minimal config
echo "rpcuser=myntarpc" >> ~/.mynta/mynta.conf
echo "rpcpassword=$(openssl rand -base64 32)" >> ~/.mynta/mynta.conf

# Start daemon
./src/myntad -daemon

# Check status
./src/mynta-cli getblockchaininfo
```

### Config File

The config file is located at `~/.mynta/mynta.conf`.

## Troubleshooting

### Line Ending Issues (Windows/WSL)

If you encounter errors like `bad interpreter: No such file or directory`, convert line endings:

```bash
dos2unix autogen.sh configure.ac Makefile.am
find . -name '*.sh' -exec dos2unix {} \;
```

### libtoolize AC_CONFIG_MACRO_DIRS Conflict

If you see an error about `AC_CONFIG_MACRO_DIRS` conflicting with `ACLOCAL_AMFLAGS`, the configure.ac files have already been patched. If building from a fresh clone and the error persists, comment out the `AC_CONFIG_MACRO_DIR` lines in:

- `configure.ac`
- `src/secp256k1/configure.ac`
- `src/univalue/configure.ac`

### Missing ui_interface.h

This header file should be present in `src/`. If missing, it can be obtained from the Ravencoin repository.

### Missing libblst.a

Build the BLST library first:

```bash
cd src/bls/blst
./build.sh
cd ../../..
```

## Notes

### Genesis Block

Mynta inherits its genesis block from Ravencoin. The original pszTimestamp is preserved for consensus compatibility:

```
"The Times 03/Jan/2018 Bitcoin is name of the game for new generation of firms"
```

### Compiler Requirements

- GCC 7+ or Clang 6+
- C++17 support required

### Known Issues

- If you encounter BerkeleyDB version errors, use `--with-incompatible-bdb`
- On newer systems with miniupnpc 2.2+, the code includes compatibility fixes
- Man page generation may fail; this is non-critical

## Verification

After building, verify the version:

```bash
./src/myntad --version
```

Expected output should show "Mynta Core" with the version number.
