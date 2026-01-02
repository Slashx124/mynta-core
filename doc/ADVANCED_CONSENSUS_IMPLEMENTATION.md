# Advanced Consensus Implementation Summary

## Branch: `feature/advanced-consensus`

This document provides a comprehensive overview of the advanced consensus features implemented for Mynta Core.

---

## 1. BLS12-381 Library Integration

### Files
- `src/bls/bls.h` - Header definitions
- `src/bls/bls.cpp` - Implementation

### Classes
- `CBLSSecretKey` - BLS secret key with secure generation
- `CBLSPublicKey` - BLS public key derived from secret
- `CBLSSignature` - BLS signature with aggregation support

### Key Features
- Secure random key generation via `MakeNewKey()`
- Deterministic key derivation from seed
- Signature creation: `secretKey.Sign(messageHash)`
- Signature verification: `sig.VerifyInsecure(pubKey, messageHash)`
- Signature aggregation: `aggSig.AggregateInsecure(sigVector)`
- Public key aggregation: `aggPk.AggregateInsecure(pkVector)`
- Full serialization support for network/disk

### Security Considerations
- Keys are securely zeroed on destruction
- Invalid keys/signatures are explicitly marked and rejected
- Null checks prevent use of uninitialized objects

### Tests
- `src/test/bls_tests.cpp`:
  - Key generation tests
  - Signing/verification tests
  - Wrong key rejection tests
  - Signature aggregation tests
  - Serialization round-trip tests
  - Invalid signature rejection
  - Null key handling

---

## 2. Masternode Quorum Signing (LLMQ)

### Files
- `src/llmq/quorums.h` - Header definitions
- `src/llmq/quorums.cpp` - Implementation

### Classes
- `CQuorum` - Represents a long-living masternode quorum
- `CQuorumMember` - Individual quorum participant
- `CQuorumManager` - Manages quorum lifecycle
- `CSigningManager` - Coordinates threshold signing
- `CRecoveredSig` - Aggregated recovered signature

### Quorum Types
- `QUORUM_TYPE_50_60` - 50 members, 60% threshold (for InstantSend)
- `QUORUM_TYPE_400_60` - 400 members, 60% threshold (for ChainLocks)

### Key Features
- Deterministic quorum selection based on block hash and request ID
- Threshold signature aggregation (t-of-n)
- Quorum rotation at predefined heights
- Automatic failure handling and recovery
- Pending share management for partial signatures

### Security Considerations
- Byzantine fault tolerance (up to 1/3 malicious members)
- Deterministic selection prevents manipulation
- Signature aggregation verifies against aggregated public key

### Tests
- `src/test/llmq_tests.cpp`:
  - Quorum creation and validation
  - Member management
  - Hash calculation consistency
  - Signing and verification workflow

---

## 3. InstantSend (Fast TX Finality)

### Files
- `src/llmq/instantsend.h` - Header definitions
- `src/llmq/instantsend.cpp` - Implementation

### Classes
- `CInstantSendLock` - Transaction input lock
- `CInstantSendManager` - Manages InstantSend lifecycle
- `CInstantSendDb` - Persistent lock storage

### Key Features
- Locks transaction inputs via quorum-signed message
- Prevents double-spend at mempool and block level
- Graceful degradation when quorum unavailable
- Input conflict detection and resolution
- Lock persistence across restarts

### Workflow
1. Transaction broadcast triggers InstantSend request
2. Quorum members vote on transaction validity
3. Threshold signatures aggregated into lock
4. Lock prevents conflicting transactions

### Security Considerations
- Only locks inputs with sufficient confirmations (optional)
- Conflict detection rejects competing locks
- Invalid signatures are rejected immediately
- Does not weaken base consensus

### Tests
- Lock creation and serialization
- Hash calculation consistency
- Input conflict detection
- Pending lock management

---

## 4. ChainLocks (51% Attack Mitigation)

### Files
- `src/llmq/chainlocks.h` - Header definitions
- `src/llmq/chainlocks.cpp` - Implementation

### Classes
- `CChainLockSig` - Block finality signature
- `CChainLocksDb` - Persistent lock storage
- `CChainLocksManager` - Manages ChainLock lifecycle

### Key Features
- Signs block hashes via masternode quorum
- Prevents reorganization of ChainLocked blocks
- Height monotonicity enforcement
- Pending lock queue for blocks not yet received
- Clean integration with fork choice logic

### Activation
- `CHAINLOCK_ACTIVATION_HEIGHT`: 1000 blocks (configurable)
- `CHAINLOCK_QUORUM_TYPE`: Uses 400-member quorum

### Workflow
1. New block arrives at chain tip
2. Quorum attempts to sign block hash
3. Threshold signatures aggregated
4. ChainLock broadcast prevents reorgs below that height

### Security Considerations
- Fake ChainLock messages rejected via signature verification
- Replayed ChainLocks rejected via height monotonicity
- Conflicting ChainLocks at same height are impossible with honest quorum
- Network partition recovery handled gracefully

### Tests
- ChainLock creation and serialization
- Height lookup and monotonicity
- Reorg protection verification
- Conflict detection

---

## 5. Full HTLC Claim/Refund Transactions

### Files
- `src/assets/atomicswap.h` - Header definitions
- `src/assets/atomicswap.cpp` - Implementation

### Namespace: `HTLCTransactions`

### Functions
- `CreateHTLC()` - Create a new HTLC output
- `ClaimHTLC()` - Claim HTLC by revealing preimage
- `RefundHTLC()` - Refund HTLC after timeout
- `ParseHTLCScript()` - Extract HTLC parameters from script
- `VerifyHTLCOutput()` - Validate HTLC output
- `GetHTLCStatus()` - Get timeout status

### HTLC Script Structure
```
OP_IF
    OP_SHA256 <hashLock> OP_EQUALVERIFY
    <receiver_pubkey_hash> OP_CHECKSIG
OP_ELSE
    <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <sender_pubkey_hash> OP_CHECKSIG
OP_ENDIF
```

### Key Features
- Secure preimage-based claims
- Time-locked refund path
- Transaction malleability protection
- Full wallet integration
- Cross-chain compatibility

### Security Considerations
- SHA256 preimage hashing
- CHECKLOCKTIMEVERIFY for timeout enforcement
- Signature verification on both paths
- Preimage extraction for counterparty proof

### Tests
- `src/test/htlc_orderbook_tests.cpp`:
  - Script creation tests
  - Preimage verification tests
  - Timeout logic tests
  - Claim/refund script creation
  - Preimage extraction
  - Serialization tests

---

## 6. Persistent Reorg-Safe Order Book

### Files
- `src/assets/atomicswap.h` - Header definitions
- `src/assets/atomicswap.cpp` - Implementation

### Class: `CPersistentOrderBook`

### Key Features
- LevelDB-backed persistent storage
- Survives daemon restarts
- UTXO-based order tracking
- Automatic rollback on chain reorg
- Deterministic order expiration
- No centralized matching

### Methods
- `AddOffer()` - Add new order with funding UTXO
- `RemoveOffer()` - Remove order
- `MarkOfferFilled()` - Mark order as filled
- `CancelOffer()` - Cancel active order
- `GetOffer()` - Retrieve order by hash
- `GetOffersForPair()` - Get orders for trading pair
- `ConnectBlock()` / `DisconnectBlock()` - Reorg handling
- `CleanupExpired()` - Prune old orders

### Consensus Integration
- Orders tied to funding UTXOs
- Spending UTXO invalidates order
- Reorg disconnects restore previous state
- Height-based expiration is deterministic

### Tests
- Order creation and retrieval
- Pair-based lookup
- Expiration cleanup
- Serialization

---

## Soak Testing

### File
- `test/functional/feature_advanced_consensus_soak.py`

### Duration Options
- 30 minutes (default)
- 60 minutes
- 4 hours

### Features Tested
- Masternode state transitions
- InstantSend transaction locking
- ChainLocks block finality
- HTLC atomic swap flows
- Order book operations
- Reorg simulation
- Memory/CPU monitoring

### Debug Levels
- `MYNTA_DEBUG=0` - Minimal output
- `MYNTA_DEBUG=1` - Verbose output (default)
- `MYNTA_DEBUG=2` - Intense protocol tracing

### Usage
```bash
# 30-minute soak test
python3 test/functional/feature_advanced_consensus_soak.py --duration=30

# 4-hour soak test with verbose output
MYNTA_DEBUG=2 python3 test/functional/feature_advanced_consensus_soak.py --duration=240
```

---

## Commit History

| Hash | Description |
|------|-------------|
| 544d29e | build: Add BLS, LLMQ, and HTLC files to build system |
| 89f33fc | feat: Implement advanced consensus features (BLS, LLMQ, InstantSend, ChainLocks, HTLC) |
| 6950f09 | docs: Add implementation summary for masternodes and DEX |
| 07a1ff6 | test: Add unit and soak tests for masternodes and DEX |
| 43c11b2 | feat(dex): Implement atomic swap and DEX primitives |

---

## Consensus-Critical Changes

The following changes affect consensus and require careful review:

1. **BLS Signature Verification**: Invalid BLS signatures cause hard rejection of transactions/blocks
2. **InstantSend Locking**: Conflicts are deterministically resolved; conflicting transactions rejected
3. **ChainLocks**: Blocks below ChainLocked height cannot be reorganized
4. **HTLC Scripts**: New script templates validated at consensus level
5. **Order Book UTXO Tracking**: Orders invalidated when funding UTXO spent

---

## Security Notes and Mitigations

| Risk | Mitigation |
|------|------------|
| BLS key reuse | Keys generated fresh; no derivation reuse |
| Replay attacks | Height-based identifiers; nonces in signatures |
| Double-spend | InstantSend locks; ChainLock prevents reorgs |
| Malleability | SegWit-style witness separation; SIGHASH_ALL |
| Quorum compromise | 60%+ threshold; deterministic rotation |
| HTLC preimage leak | SHA256 hashing; timeout for refund |
| Order manipulation | UTXO-based; no privileged matching |

---

## Reviewer Instructions

1. **Build and Test**
   ```bash
   cd mynta-core
   ./autogen.sh
   ./configure
   make -j$(nproc)
   make check
   ```

2. **Run Unit Tests**
   ```bash
   src/test/test_raven --run_test=bls_tests
   src/test/test_raven --run_test=llmq_tests
   src/test/test_raven --run_test=htlc_orderbook_tests
   ```

3. **Run Soak Test**
   ```bash
   python3 test/functional/feature_advanced_consensus_soak.py --duration=30
   ```

4. **Review Consensus Changes**
   - Focus on `src/bls/`, `src/llmq/`, `src/evo/`
   - Verify signature verification paths
   - Check for edge cases in reorg handling

5. **Security Review**
   - Verify no bypass of BLS verification
   - Check InstantSend conflict resolution
   - Validate ChainLock height enforcement

