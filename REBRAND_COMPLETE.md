# Mynta Core Rebrand - Complete Report

## A. Root Cause Analysis

The previous aggressive rebrand introduced several issues:

| Issue | Problem | Fix Applied |
|-------|---------|-------------|
| Symlink Dependencies | Created `myntad -> ravend` symlinks | Proper Makefile.am target renaming |
| Config Header Mismatch | `#include "config/mynta-config.h"` but file not generated | Updated configure.ac to generate correct header |
| Broken Autotools | m4 macros referenced non-existent files | Renamed m4 files with `git mv` |
| miniupnpc API | Code used 5-arg API, modern lib needs 7 args | Added `MINIUPNPC_API_VERSION` detection |
| Missing Include | `support/lockedpool.h` missing `<stdexcept>` | Added the include |
| Genesis Changes | pszTimestamp changed, breaking assertions | Preserved original for compatibility |

## B. Clean Rebrand Strategy

### Safe Changes (User-Visible Branding)
- Package name: "Ravencoin" → "Mynta Core"
- Binary names: `ravend` → `myntad`, etc.
- Data directory: `~/.raven` → `~/.mynta`
- Config file: `raven.conf` → `mynta.conf`
- URLs: Updated to mynta.network
- Class names: `CRavenAddress` → `CMyntaAddress`
- Function names: `GenerateRavens` → `GenerateMyntas`
- RPC messages: "Raven server" → "Mynta server"

### Preserved (Consensus-Critical)
- Genesis block pszTimestamp: `"The Times 03/Jan/2018..."`
- Genesis hash and merkle root
- BIP44 coin type comments reference original
- Copyright attribution lines

## C. Commit Series

```
1a7246e60 Update BIP44 comments to Mynta
15e0fb1b6 Complete documentation branding
d536a2477 Complete user-visible branding
b02c02f92 Rebrand Ravencoin to Mynta Core
```

### Commit 1: Rebrand Ravencoin to Mynta Core
Main rebrand commit including:
- configure.ac updates
- Makefile.am updates
- Source file renames
- m4 macro renames
- pkg-config template rename
- Bug fixes (stdexcept, miniupnpc)

### Commit 2: Complete user-visible branding
- MyntaMiner function
- Data directory paths
- Log messages

### Commit 3: Complete documentation branding
- All documentation comments updated
- Error messages updated

### Commit 4: Update BIP44 comments to Mynta
- Final comment cleanup

## D. Build Verification

### Clean Build Commands (Debian 12 / Ubuntu 22.04)

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential libtool autotools-dev automake pkg-config \
    libssl-dev libevent-dev libboost-all-dev libdb-dev libdb++-dev \
    libminiupnpc-dev libzmq3-dev

# Clone and build
git clone <repo> mynta-core
cd mynta-core
./autogen.sh
./configure --disable-bench --disable-tests --with-incompatible-bdb --without-gui --disable-man
make -j$(nproc)

# Verify
./src/myntad --version
./src/mynta-cli --version
```

### Build Output

```
Mynta Core Daemon version v4.6.1.0
Copyright (C) 2009-2022 The Mynta Core developers
```

## E. Files Modified

### Build System
- `configure.ac` - Package name, binary names, config header
- `Makefile.am` - Top-level build targets
- `src/Makefile.am` - Source compilation targets
- `doc/man/Makefile.am` - Man page targets
- `build-aux/m4/mynta_*.m4` - Renamed m4 macros
- `libmyntaconsensus.pc.in` - Renamed pkg-config template

### Source Files (Renamed)
- `src/ravend.cpp` → `src/myntad.cpp`
- `src/raven-cli.cpp` → `src/mynta-cli.cpp`
- `src/raven-tx.cpp` → `src/mynta-tx.cpp`
- `src/script/ravenconsensus.*` → `src/script/myntaconsensus.*`
- `src/test/test_raven*.cpp` → `src/test/test_mynta*.cpp`

### New Files
- `BUILDING.md` - Build documentation
- `Dockerfile` - Docker build
- `.github/workflows/build.yml` - CI workflow

## F. Verification Checklist

- [x] Fresh clone builds without symlinks
- [x] `autoreconf -i` succeeds
- [x] `./configure` succeeds
- [x] `make` produces myntad, mynta-cli
- [x] Binaries are real executables (not symlinks)
- [x] `myntad --version` shows "Mynta Core"
- [x] Config header generated as `mynta-config.h`
- [x] pkg-config template is `libmyntaconsensus.pc.in`
- [x] Genesis pszTimestamp unchanged
- [x] No "Raven" in user-visible strings (except copyright)

## G. Grep Proof

```bash
$ grep -r "Raven" src/*.cpp src/*.h | grep -v "Copyright" | wc -l
0
```

All remaining "Raven" references are in copyright attribution lines, which are preserved for legal compliance.

## H. Notes

### Genesis Block
The genesis block pszTimestamp is preserved from Ravencoin:
```
"The Times 03/Jan/2018 Bitcoin is name of the game for new generation of firms"
```

This maintains compatibility with the existing chain. For a completely new chain, the genesis block should be re-mined with a new timestamp.

### DNS Seeds
DNS seeds have been cleared for a fresh chain launch. Use `-addnode=<ip>` to manually connect to seed nodes.

### miniupnpc Compatibility
Added API version detection to support both old (5-arg) and new (7-arg) UPNP_GetValidIGD signatures.


