# Mynta Core: Masternode & DEX Implementation Summary

## Overview

This document summarizes the implementation of deterministic masternodes and decentralized exchange (DEX) capabilities for Mynta Core.

## 1. Deterministic Masternodes

### Architecture

Based on Dash DIP-003 design principles, adapted for Mynta:

```
┌─────────────────────────────────────────────────────────────────┐
│                     DETERMINISTIC MASTERNODE SYSTEM             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │  ProRegTx   │───▶│     DML     │◀───│  CDeterministicMN   │ │
│  │  ProUpServTx│    │  (on-chain) │    │  Manager            │ │
│  │  ProUpRegTx │    │             │    │                     │ │
│  │  ProUpRevTx │    └─────────────┘    └─────────────────────┘ │
│  └─────────────┘           │                    │              │
│         │                  │                    │              │
│         ▼                  ▼                    ▼              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │  Consensus  │    │   Payment   │    │       EvoDB         │ │
│  │  Validation │    │  Selection  │    │   (persistence)     │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| `src/evo/evodb.{h,cpp}` | Database for masternode state persistence |
| `src/evo/providertx.{h,cpp}` | Special transaction types for MN management |
| `src/evo/deterministicmns.{h,cpp}` | Deterministic masternode list management |
| `src/evo/specialtx.h` | Helper functions for special transactions |
| `src/rpc/masternode.{h,cpp}` | RPC interface for masternode operations |

### Transaction Types

1. **ProRegTx** (Type 1): Register a new masternode
   - Collateral reference (10,000 MYNTA UTXO)
   - Owner/Operator/Voting keys
   - IP address and port
   - Payout address
   - Operator reward percentage

2. **ProUpServTx** (Type 2): Update service info
   - New IP address/port
   - Signed by operator key

3. **ProUpRegTx** (Type 3): Update registration
   - New operator/voting keys
   - New payout address
   - Signed by owner key

4. **ProUpRevTx** (Type 4): Revoke registration
   - Revocation reason
   - Signed by operator key

### State Machine

```
REGISTERED → ENABLED → POSE_BANNED → REVOKED
     │           │           │
     │           └───────────┘ (revival)
     │
     └─────────────────────────────────────→ REVOKED (collateral spent)
```

### Payment Selection

Deterministic selection based on:
1. Only ENABLED masternodes eligible
2. Score = SHA256(proTxHash || blockHash)
3. Lowest score wins
4. Enforced at consensus level

---

## 2. DEX / Atomic Swaps

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      ATOMIC SWAP SYSTEM                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   Offers    │───▶│  Order Book │◀───│       HTLC          │ │
│  │             │    │             │    │   (Hash Time-Lock)  │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
│         │                  │                    │              │
│         ▼                  ▼                    ▼              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │    Maker    │    │    Taker    │    │   P2SH Scripts      │ │
│  │   creates   │◀──▶│   accepts   │    │   (claim/refund)    │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| `src/assets/atomicswap.{h,cpp}` | HTLC and swap logic |
| `src/rpc/dex.cpp` | DEX RPC commands |

### HTLC Structure

```
OP_IF
    # Claim path (receiver reveals preimage)
    OP_SHA256 <hashLock> OP_EQUALVERIFY
    <receiver_pubkey_hash> OP_CHECKSIG
OP_ELSE
    # Refund path (sender reclaims after timeout)
    <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <sender_pubkey_hash> OP_CHECKSIG
OP_ENDIF
```

### Swap Flow

1. **Maker creates offer** with hash lock (secret hidden)
2. **Taker accepts** and creates matching HTLC
3. **Maker claims** taker's HTLC, revealing preimage
4. **Taker uses preimage** to claim maker's HTLC
5. Both parties receive their funds atomically

---

## 3. Consensus-Critical Changes

### Modified Files

| File | Change |
|------|--------|
| `src/primitives/transaction.{h,cpp}` | Added `nType` and `vExtraPayload` fields for special transactions |
| `src/rpc/register.h` | Added masternode and DEX RPC registration |

### Transaction Format (Version 3+)

```
nVersion (32-bit, lower 16 bits = version, upper 16 bits = type)
vin[]
vout[]
nLockTime
vExtraPayload (if nType != 0)
```

---

## 4. RPC Commands

### Masternode Commands

```bash
# List masternodes
mynta-cli masternode list

# Get masternode count
mynta-cli masternode count

# Get next payment winners
mynta-cli masternode winner 10

# Register new masternode
mynta-cli protx register <collateral_hash> <index> <ip:port> <owner_addr> <operator_pubkey> <voting_addr> <op_reward> <payout_addr>

# List ProTx registrations
mynta-cli protx list

# Get ProTx info
mynta-cli protx info <proTxHash>
```

### DEX Commands

```bash
# View order book
mynta-cli dex orderbook MYTOKEN

# Create swap offer
mynta-cli dex createoffer MYTOKEN 100 MYNTA 50

# Accept offer
mynta-cli dex takeoffer <offer_hash>

# Cancel offer
mynta-cli dex canceloffer <offer_hash>

# Create raw HTLC
mynta-cli htlc create <receiver_addr> <amount> <hash_lock> <timeout_blocks>
```

---

## 5. Testing

### Unit Tests

```bash
# Run all unit tests
make check

# Specific test files:
# - src/test/evo_deterministicmns_tests.cpp
# - src/test/atomicswap_tests.cpp
```

### Functional Tests

```bash
# Run soak test (30 minutes)
./test/functional/feature_masternode_soak.py

# Extended soak (4 hours)
./test/functional/feature_masternode_soak.py --duration=240

# With verbose logging
MYNTA_DEBUG=1 ./test/functional/feature_masternode_soak.py
```

### Soak Test Coverage

- Continuous block production
- Masternode registration/update/revocation
- Asset creation and transfers
- Chain reorganization simulation
- Invalid transaction rejection
- Consensus divergence detection
- Memory monitoring

---

## 6. Security Considerations

### Masternode Security

- All state derived from chain (no trusted third parties)
- BLS signatures for operator authentication
- Collateral locking prevents double-registration
- Replay protection via inputs hash

### DEX Security

- SHA256 preimage requirement for claims
- CHECKLOCKTIMEVERIFY for timeout enforcement
- Deterministic script generation
- No centralized order matching

---

## 7. Future Work

1. **BLS Library Integration**: Full BLS signature verification
2. **Quorum Signing**: Multi-masternode signatures for enhanced security
3. **InstantSend**: Masternode-backed instant transaction confirmations
4. **ChainLocks**: Protection against 51% attacks
5. **Full HTLC Transaction Creation**: Complete claim/refund transaction building
6. **Persistent Order Book**: Database-backed DEX orders

---

## 8. Build Instructions

```bash
# Standard build
./autogen.sh
./configure
make

# Run tests
make check

# Build and run daemon
./src/myntad -regtest
./src/mynta-cli -regtest masternode count
```

---

## 9. Specification Documents

- [MIP-001: Deterministic Masternodes](masternode/MIP-001-DETERMINISTIC-MASTERNODES.md)

---

*Document Version: 1.0*
*Last Updated: 2026-01-02*

