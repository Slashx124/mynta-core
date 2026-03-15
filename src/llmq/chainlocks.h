// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MYNTA_LLMQ_CHAINLOCKS_H
#define MYNTA_LLMQ_CHAINLOCKS_H

#include "llmq/quorums.h"
#include "evo/evodb.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"

#include <atomic>
#include <map>
#include <memory>
#include <set>

class CBlock;
class CBlockIndex;
class CValidationState;
class CEvoDB;

namespace llmq {

/**
 * ChainLocks - 51% Attack Mitigation
 * 
 * ChainLocks prevent blockchain reorganizations by having masternode
 * quorums sign block hashes. Once a block is "ChainLocked", it cannot
 * be reorganized away even if an attacker has majority hash power.
 * 
 * How it works:
 * 1. When a new block is found, a quorum is selected to sign it
 * 2. If the quorum reaches threshold, a ChainLock signature is created
 * 3. Once a ChainLock is received, the block becomes immutable
 * 4. Any competing chain without the ChainLock is rejected
 * 
 * Security:
 * - Requires honest quorum majority (> threshold)
 * - Height must be strictly increasing (no rollbacks)
 * - Signature must verify against known quorum
 * - Protected against replay attacks via height binding
 */

// Quorum type used for ChainLocks (larger quorum for security)
static const LLMQType CHAINLOCK_QUORUM_TYPE = LLMQType::LLMQ_400_60;

// ============================================================
// CONDITIONAL CHAINLOCKS ACTIVATION (Consensus-Safe)
//
// ChainLocks use a deterministic, deferred activation mechanism:
//
// 1. Activation is ATTEMPTED every CHAINLOCK_ACTIVATION_INTERVAL blocks
// 2. Activation SUCCEEDS only if:
//    - Deterministic masternode count >= LLMQ minSize (300 for LLMQ_400_60)
//    - Masternodes are PoSe-valid
// 3. If conditions NOT met:
//    - Activation is DEFERRED
//    - Next attempt at next interval boundary
// 4. Once activated:
//    - ChainLocks are PERMANENTLY enabled
//    - No automatic deactivation or flapping
//
// This ensures ChainLocks never activate before quorums are viable,
// and activation state is deterministically derivable from chain data.
//
// The earliest possible activation is at CHAINLOCK_MIN_ACTIVATION_HEIGHT.
// Before this height, no activation attempts are made even at interval
// boundaries. This allows masternode network to bootstrap.
// ============================================================

// Minimum height before any activation can be attempted
// (MN activation height 1000 + DKG interval 288 + buffer 212 = 1500)
static const int CHAINLOCK_MIN_ACTIVATION_HEIGHT = 1500;

// Interval between activation attempts (blocks)
static const int CHAINLOCK_ACTIVATION_INTERVAL = 5000;

// Required masternode count for activation (must match LLMQ_400_60 minSize)
static const int CHAINLOCK_REQUIRED_MASTERNODES = 300;

// ============================================================
// ChainLocks Activation Status (for RPC observability)
// ============================================================
enum class ChainLockActivationReason : uint8_t {
    ENABLED = 0,                    // ChainLocks are enabled
    BEFORE_MIN_HEIGHT = 1,          // Haven't reached minimum activation height
    INSUFFICIENT_MASTERNODES = 2,   // Not enough valid masternodes
    NO_VALID_QUORUM = 3,            // No valid quorum available for signing
    WAITING_NEXT_INTERVAL = 4,      // Waiting for next activation attempt boundary
};

// Get human-readable string for activation reason
inline std::string ChainLockReasonToString(ChainLockActivationReason reason) {
    switch (reason) {
        case ChainLockActivationReason::ENABLED:
            return "enabled";
        case ChainLockActivationReason::BEFORE_MIN_HEIGHT:
            return "before_minimum_height";
        case ChainLockActivationReason::INSUFFICIENT_MASTERNODES:
            return "insufficient_masternodes";
        case ChainLockActivationReason::NO_VALID_QUORUM:
            return "no_valid_quorum";
        case ChainLockActivationReason::WAITING_NEXT_INTERVAL:
            return "waiting_next_interval";
        default:
            return "unknown";
    }
}

/**
 * CChainLockSig - A ChainLock signature
 */
class CChainLockSig
{
public:
    int nHeight{0};          // Block height
    uint256 blockHash;       // Block hash at this height
    CBLSSignature sig;       // Quorum threshold signature
    
    // Cached hash (thread-safe via atomic flag)
    mutable uint256 hash;
    mutable std::atomic<bool> hashCached{false};

public:
    CChainLockSig() = default;
    CChainLockSig(int _nHeight, const uint256& _blockHash)
        : nHeight(_nHeight), blockHash(_blockHash) {}
    CChainLockSig(const CChainLockSig& o)
        : nHeight(o.nHeight), blockHash(o.blockHash), sig(o.sig), hash(), hashCached(false) {}
    CChainLockSig& operator=(const CChainLockSig& o)
    {
        if (this != &o) {
            nHeight = o.nHeight; blockHash = o.blockHash; sig = o.sig;
            hash = uint256(); hashCached.store(false, std::memory_order_relaxed);
        }
        return *this;
    }
    CChainLockSig(CChainLockSig&& o) noexcept
        : nHeight(o.nHeight), blockHash(std::move(o.blockHash)), sig(std::move(o.sig)),
          hash(), hashCached(false) {}
    CChainLockSig& operator=(CChainLockSig&& o) noexcept
    {
        if (this != &o) {
            nHeight = o.nHeight; blockHash = std::move(o.blockHash); sig = std::move(o.sig);
            hash = uint256(); hashCached.store(false, std::memory_order_relaxed);
        }
        return *this;
    }
    
    uint256 GetHash() const;
    
    // Build the signing hash
    uint256 GetSignHash() const;
    
    // Build the request ID for signing
    uint256 GetRequestId() const;
    
    bool IsNull() const { return nHeight == 0 && blockHash.IsNull(); }
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nHeight);
        READWRITE(blockHash);
        READWRITE(sig);
    }
    
    bool operator==(const CChainLockSig& other) const {
        return nHeight == other.nHeight && blockHash == other.blockHash;
    }
    
    std::string ToString() const;
};

/**
 * CChainLocksDb - Persistent storage for ChainLocks
 * 
 * CRITICAL: This class now persists ChainLock signatures to disk via evoDb.
 * On restart, all ChainLocks are loaded from disk to maintain reorg protection.
 * 
 * Database keys:
 * - DB_CHAINLOCK_BY_HEIGHT: Maps height -> CChainLockSig
 * - DB_CHAINLOCK_BY_HASH: Maps blockHash -> CChainLockSig  
 * - DB_CHAINLOCK_BEST: Stores best ChainLock height and hash
 */
class CChainLocksDb
{
private:
    mutable CCriticalSection cs;
    
    // Reference to evolution database for persistence
    CEvoDB& evoDb;
    
    // In-memory cache of ChainLocks by height
    std::map<int, CChainLockSig> locksByHeight;
    
    // In-memory cache of ChainLocks by block hash
    std::map<uint256, CChainLockSig> locksByHash;
    
    // Best ChainLock height and hash
    int bestChainLockHeight{0};
    uint256 bestChainLockHash;
    
    // Database key prefixes
    static const std::string DB_CHAINLOCK_BY_HEIGHT;
    static const std::string DB_CHAINLOCK_BY_HASH;
    static const std::string DB_CHAINLOCK_BEST_HEIGHT;
    static const std::string DB_CHAINLOCK_BEST_HASH;

public:
    explicit CChainLocksDb(CEvoDB& _evoDb);
    
    // Initialize from database - MUST be called at startup
    bool Init();
    
    // Persist best height/hash to disk (called automatically)
    bool Flush();
    
    // Write a ChainLock (persists to disk immediately)
    bool WriteChainLock(const CChainLockSig& clsig);
    
    // Get ChainLock by height
    bool GetChainLock(int nHeight, CChainLockSig& clsigOut) const;
    
    // Get ChainLock by block hash
    bool GetChainLockByHash(const uint256& blockHash, CChainLockSig& clsigOut) const;
    
    // Check if a block is ChainLocked
    bool IsChainLocked(int nHeight) const;
    bool HasChainLock(const uint256& blockHash) const;
    
    // Get best ChainLock
    int GetBestChainLockHeight() const;
    uint256 GetBestChainLockHash() const;
    
    // Remove ChainLocks above a certain height (for cleanup/reorg)
    void RemoveAboveHeight(int nHeight);
};

/**
 * CChainLocksManager - Manages ChainLock creation and validation
 * 
 * CRITICAL: This class now persists chainLockActivationHeight to disk.
 * On restart, activation state is restored to prevent consensus divergence.
 */
class CChainLocksManager
{
private:
    mutable CCriticalSection cs;
    
    // Reference to evolution database for persistence
    CEvoDB& evoDb;
    
    // Persistent ChainLock storage
    CChainLocksDb db;
    
    // Reference to signing manager
    CSigningManager& signingManager;
    CQuorumManager& quorumManager;
    
    // Our node's proTxHash
    uint256 myProTxHash;
    
    // Best known ChainLock
    CChainLockSig bestChainLock;
    const CBlockIndex* bestChainLockBlockIndex{nullptr};
    
    // Pending ChainLock signatures being collected
    std::map<int, CChainLockSig> pendingChainLocks;
    
    // Block heights we're trying to sign
    std::set<int> signingHeights;
    
    // Last cleanup height
    int lastCleanupHeight{0};
    
    // ============================================================
    // CONDITIONAL ACTIVATION STATE
    // Persisted to evoDb. Once set to non-zero, ChainLocks are 
    // permanently enabled. Loaded from disk on restart.
    // ============================================================
    int chainLockActivationHeight{0};
    
    // Database key for activation height persistence
    static const std::string DB_CHAINLOCK_ACTIVATION_HEIGHT;

public:
    CChainLocksManager(CEvoDB& _evoDb, CSigningManager& _signingManager, CQuorumManager& _quorumManager);
    
    // Initialize from database - MUST be called at startup
    bool Init();
    
    // Set our identity
    void SetMyProTxHash(const uint256& _proTxHash) { myProTxHash = _proTxHash; }
    
    // Process a new block
    void ProcessNewBlock(const CBlock& block, const CBlockIndex* pindex);
    
    // Try to sign a ChainLock for a block
    bool TrySignChainLock(const CBlockIndex* pindex);
    
    // Process a received ChainLock
    bool ProcessChainLock(const CChainLockSig& clsig, CValidationState& state);
    
    // Check if ChainLocks are enabled at this height
    bool IsChainLockActive() const;
    
    // ============================================================
    // CONDITIONAL ACTIVATION API (Consensus-Safe)
    // These methods derive state entirely from chain data.
    // No network state, peer availability, or local clocks used.
    // ============================================================
    
    // Get the activation height (0 if not yet activated)
    int GetActivationHeight() const;
    
    // Get the height of the next activation attempt (0 if already activated)
    int GetNextActivationAttemptHeight() const;
    
    // Get the current count of PoSe-valid masternodes
    int GetEligibleMasternodeCount() const;
    
    // Get the activation status and reason
    ChainLockActivationReason GetActivationStatus() const;
    
    // Check if activation should be attempted at this height
    // Returns true only at CHAINLOCK_ACTIVATION_INTERVAL boundaries
    bool ShouldAttemptActivation(int nHeight) const;
    
    // Attempt activation (called at interval boundaries during block processing)
    // Returns true if activation succeeded
    bool TryActivate(int nHeight);
    
    // Set activation height (used during block processing and reorgs)
    void SetActivationHeight(int nHeight);
    
    // Check if a block is ChainLocked
    bool IsChainLocked(int nHeight) const;
    bool HasChainLock(const uint256& blockHash) const;
    bool HasChainLock(const CBlockIndex* pindex) const;
    
    // Get the best ChainLock
    CChainLockSig GetBestChainLock() const;
    int GetBestChainLockHeight() const;
    
    // Check if a block can be reorganized away
    // Returns false if the block is protected by ChainLock
    bool CanReorg(const CBlockIndex* pindexNew, const CBlockIndex* pindexOld) const;
    
    // Verify a ChainLock signature
    bool VerifyChainLock(const CChainLockSig& clsig) const;
    
    // Fork choice rule: prefer ChainLocked chain
    bool ShouldPreferChainLocked(const CBlockIndex* pindexA, const CBlockIndex* pindexB) const;
    
    // Update on new chain tip
    void UpdatedBlockTip(const CBlockIndex* pindex);
    
    // Cleanup
    void Cleanup();

private:
    // Create request ID for a height
    uint256 CreateRequestId(int nHeight) const;
    
    // Sign a ChainLock
    bool SignChainLock(const CBlockIndex* pindex);
    
    // Check if we should sign at this height
    bool ShouldSignAt(int nHeight) const;
    
    // Select quorum for ChainLock at given height
    CQuorumCPtr SelectQuorum(const CBlockIndex* pindex) const;
};

// Global instance
extern std::unique_ptr<CChainLocksManager> chainLocksManager;

// Initialization - evoDb MUST be passed for persistence
void InitChainLocks(CEvoDB& evoDb, CSigningManager& signingManager, CQuorumManager& quorumManager);
void StopChainLocks();

// Validation integration
bool CheckAgainstChainLocks(const CBlockIndex* pindex, CValidationState& state);

} // namespace llmq

#endif // MYNTA_LLMQ_CHAINLOCKS_H






