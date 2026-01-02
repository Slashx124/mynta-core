# Root Cause Analysis: Mynta Rebrand Issues

## A. Issues Introduced by Aggressive Rebrand

### Issue 1: Symlink Dependencies for Binaries
**Problem:** Created symlinks `myntad -> ravend` and `mynta-cli -> raven-cli` instead of properly renaming build targets.
**Impact:** Builds produce wrong binary names; symlinks break on fresh clone.
**Correct Fix:** Update `src/Makefile.am` to define `myntad` and `mynta-cli` as actual build targets.

### Issue 2: Config Header Include Mismatch  
**Problem:** sed replaced `#include "config/raven-config.h"` with `#include "config/mynta-config.h"` in source files, but no such file exists.
**Impact:** Build fails with "file not found" errors.
**Correct Fix:** 
- Either update `configure.ac` to generate `src/config/mynta-config.h`, OR
- Revert include statements and keep original config header name.

### Issue 3: Consensus Header Symlink
**Problem:** Created `myntaconsensus.h -> aicoinconsensus.h` symlink.
**Impact:** Missing header on fresh clone.
**Correct Fix:** Rename actual file and update all references consistently, or keep original name.

### Issue 4: Genesis pszTimestamp Changed
**Problem:** sed replaced "AiCoin Genesis" with "Mynta Genesis" in pszTimestamp.
**Impact:** Changes genesis block hash, breaks hardcoded assertions, makes chain incompatible.
**Correct Fix:** Either:
- Revert pszTimestamp and document it as historical (Option A), OR
- Re-mine genesis with new timestamp and update all assertions (Option B)

### Issue 5: Generated Header Edits
**Problem:** Edited `src/config/raven-config.h` directly to fix branding.
**Impact:** Changes lost on reconfigure; not a proper fix.
**Correct Fix:** Edit `configure.ac` variables (PACKAGE_NAME, COPYRIGHT_HOLDERS_SUBSTITUTION, URLs) and regenerate.

### Issue 6: Broken Autotools Inputs
**Problem:** Some templates were deleted or renamed inconsistently.
**Impact:** autoreconf fails; configure fails.
**Correct Fix:** Properly rename all templates (.in files) and update configure.ac references.

### Issue 7: pkg-config Template Mismatch
**Problem:** `libravenconsensus.pc.in` not renamed to match new library name.
**Impact:** Installed pkg-config file has wrong names.
**Correct Fix:** Rename template and update configure.ac to generate correct file.

### Issue 8: miniupnpc API Incompatibility
**Problem:** Code uses old UPNP_GetValidIGD signature (5 args), but modern library requires 7 args.
**Impact:** Build fails unless --without-miniupnpc.
**Correct Fix:** Add autoconf detection for API version and use appropriate call signature.

### Issue 9: Missing stdexcept Include
**Problem:** `src/support/lockedpool.h` doesn't include `<stdexcept>`.
**Impact:** Build fails with modern compilers (clang 17+).
**Correct Fix:** Add the missing include (this is a bug fix, not rebrand-related).

---

## B. Clean Rebrand Strategy

### SAFE Changes (User-Visible Branding Only)
These can be changed without consensus implications:
- `configure.ac`: PACKAGE_NAME, PACKAGE_URL, COPYRIGHT_HOLDERS_SUBSTITUTION
- `src/clientversion.cpp`: CLIENT_NAME
- RPC help strings: "Raven address" → "Mynta address"
- Error messages: "Raven server" → "Mynta server"
- Documentation and comments

### UNSAFE Changes (Consensus-Critical)
These affect chain identity and require full regeneration:
- `pszTimestamp` in chainparams.cpp
- `nTime`, `nNonce`, `nBits` for genesis
- `hashGenesisBlock` assertions
- Network magic bytes
- Address prefixes

### Decision for This Rebrand
**Option A (Conservative):** Keep original genesis/consensus values from Ravencoin fork.
- pszTimestamp: Keep original ("The Times 03/Jan/2009...")
- Genesis hash: Keep original assertions
- Branding: Change only user-visible strings

**Option B (New Chain):** Full chain identity reset.
- Requires re-mining genesis for mainnet and testnet
- All clients must use new chain from block 0
- No backward compatibility with Ravencoin

**Recommendation:** Option A for stability, unless explicitly launching new chain.

---

## C. File Renaming Strategy

### Source Files (git mv)
```
src/ravend.cpp          → src/myntad.cpp
src/raven-cli.cpp       → src/mynta-cli.cpp  
src/raven-tx.cpp        → src/mynta-tx.cpp
```

### Build System Updates
```
configure.ac:
  RAVEN_DAEMON_NAME=ravend  → MYNTA_DAEMON_NAME=myntad
  RAVEN_CLI_NAME=raven-cli  → MYNTA_CLI_NAME=mynta-cli
  RAVEN_TX_NAME=raven-tx    → MYNTA_TX_NAME=mynta-tx
  AC_INIT([Raven Core]...)  → AC_INIT([Mynta Core]...)
  CONFIG_HEADERS([src/config/raven-config.h]) → CONFIG_HEADERS([src/config/mynta-config.h])

src/Makefile.am:
  bin_PROGRAMS += ravend    → bin_PROGRAMS += myntad
  ravend_SOURCES = ...      → myntad_SOURCES = ...
  (all target references)
```

### Templates
```
libravenconsensus.pc.in → libmyntaconsensus.pc.in
```

### Header Guards (Optional but Thorough)
```
#ifndef RAVEN_*  → #ifndef MYNTA_*
```

---

## D. Verification Checklist

- [ ] Fresh clone builds without symlinks
- [ ] `./configure && make` succeeds
- [ ] Binary names are myntad, mynta-cli, mynta-tx
- [ ] `myntad --version` shows "Mynta Core"
- [ ] Network subversion shows "/Mynta:x.x.x/"
- [ ] Genesis hash matches expected (unchanged if Option A)
- [ ] No remaining "Raven" in user-visible strings (except historical consensus data)
- [ ] pkg-config file installs as libmyntaconsensus.pc


