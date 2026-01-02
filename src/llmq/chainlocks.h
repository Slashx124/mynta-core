// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MYNTA_LLMQ_CHAINLOCKS_H
#define MYNTA_LLMQ_CHAINLOCKS_H

#include "llmq/quorums.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"

#include <map>
#include <memory>
#include <set>

class CBlock;
class CBlockIndex;
class CValidationState;

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

// Minimum height before ChainLocks activate
static const int CHAINLOCK_ACTIVATION_HEIGHT = 1000;

/**
 * CChainLockSig - A ChainLock signature
 */
class CChainLockSig
{
public:
    int nHeight{0};          // Block height
    uint256 blockHash;       // Block hash at this height
    CBLSSignature sig;       // Quorum threshold signature
    
    // Cached hash
    mutable uint256 hash;
    mutable bool hashCached{false};

public:
    CChainLockSig() = default;
    CChainLockSig(int _nHeight, const uint256& _blockHash)
        : nHeight(_nHeight), blockHash(_blockHash) {}
    
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
 */
class CChainLocksDb
{
private:
    mutable CCriticalSection cs;
    
    // ChainLocks by height
    std::map<int, CChainLockSig> locksByHeight;
    
    // ChainLocks by block hash
    std::map<uint256, CChainLockSig> locksByHash;
    
    // Best ChainLock height
    int bestChainLockHeight{0};
    uint256 bestChainLockHash;

public:
    CChainLocksDb() = default;
    
    // Write a ChainLock
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
    
    // Remove ChainLocks above a certain height (for cleanup)
    void RemoveAboveHeight(int nHeight);
};

/**
 * CChainLocksManager - Manages ChainLock creation and validation
 */
class CChainLocksManager
{
private:
    mutable CCriticalSection cs;
    
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

public:
    CChainLocksManager(CSigningManager& _signingManager, CQuorumManager& _quorumManager);
    
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

// Initialization
void InitChainLocks(CSigningManager& signingManager, CQuorumManager& quorumManager);
void StopChainLocks();

// Validation integration
bool CheckAgainstChainLocks(const CBlockIndex* pindex, CValidationState& state);

} // namespace llmq

#endif // MYNTA_LLMQ_CHAINLOCKS_H

