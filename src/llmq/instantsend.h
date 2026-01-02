// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MYNTA_LLMQ_INSTANTSEND_H
#define MYNTA_LLMQ_INSTANTSEND_H

#include "llmq/quorums.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"

#include <map>
#include <memory>
#include <set>
#include <vector>

class CBlockIndex;
class CTxMemPool;
class CValidationState;

namespace llmq {

/**
 * InstantSend - Fast transaction finality via masternode quorum locks
 * 
 * How it works:
 * 1. User broadcasts transaction
 * 2. Masternodes in the selected quorum sign the transaction inputs
 * 3. Once threshold signatures are collected, inputs are "locked"
 * 4. Locked inputs cannot be double-spent even in a reorg
 * 5. Wallet can treat locked TX as "confirmed" immediately
 * 
 * Security:
 * - Requires honest quorum majority
 * - Fallback to normal confirmation if quorum unavailable
 * - Mempool enforces input locks
 * - Block validation enforces locks
 */

// Quorum type used for InstantSend
static const LLMQType INSTANTSEND_QUORUM_TYPE = LLMQType::LLMQ_50_60;

// Maximum inputs per InstantSend TX
static const int INSTANTSEND_MAX_INPUTS = 32;

// InstantSend input timeout (blocks)
static const int INSTANTSEND_LOCK_TIMEOUT = 24;

/**
 * CInstantSendInput - An input to be locked
 */
struct CInstantSendInput
{
    COutPoint outpoint;
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(outpoint);
    }
    
    bool operator==(const CInstantSendInput& other) const {
        return outpoint == other.outpoint;
    }
    
    bool operator<(const CInstantSendInput& other) const {
        return outpoint < other.outpoint;
    }
};

/**
 * CInstantSendLock - A quorum-signed lock on a transaction
 */
class CInstantSendLock
{
public:
    // The inputs being locked (hashed as the signing id)
    std::vector<COutPoint> inputs;
    
    // The transaction being locked
    uint256 txid;
    
    // The quorum that signed
    uint256 quorumHash;
    
    // The recovered threshold signature
    CBLSSignature sig;
    
    // Cached hash
    mutable uint256 hash;
    mutable bool hashCached{false};
    
public:
    CInstantSendLock() = default;
    
    uint256 GetHash() const;
    
    // Build the ID for signing (hash of inputs)
    uint256 GetRequestId() const;
    
    // Build the message hash for signing
    uint256 GetSignHash() const;
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(inputs);
        READWRITE(txid);
        READWRITE(quorumHash);
        READWRITE(sig);
    }
    
    std::string ToString() const;
};

/**
 * CInstantSendDb - Persistent storage for InstantSend locks
 */
class CInstantSendDb
{
private:
    mutable CCriticalSection cs;
    
    // Locks by input (for conflict detection)
    std::map<COutPoint, uint256> inputLocks; // outpoint -> islock hash
    
    // Locks by txid
    std::map<uint256, CInstantSendLock> locksById;
    
    // Lock hashes by txid
    std::map<uint256, uint256> txidToLockHash;

public:
    CInstantSendDb() = default;
    
    // Write a lock
    bool WriteLock(const CInstantSendLock& islock);
    
    // Get lock by hash
    bool GetLock(const uint256& hash, CInstantSendLock& islockOut) const;
    
    // Get lock by txid
    bool GetLockByTxid(const uint256& txid, CInstantSendLock& islockOut) const;
    
    // Check if an input is locked
    bool IsInputLocked(const COutPoint& outpoint) const;
    
    // Check if a tx is locked
    bool IsTxLocked(const uint256& txid) const;
    
    // Get the lock for an input
    bool GetLockForInput(const COutPoint& outpoint, CInstantSendLock& islockOut) const;
    
    // Remove a lock (for reorg)
    void RemoveLock(const uint256& hash);
    
    // Remove locks for a set of txids
    void RemoveLocksForTxids(const std::set<uint256>& txids);
    
    // Get all locked outpoints
    std::set<COutPoint> GetAllLockedOutpoints() const;
};

/**
 * CInstantSendManager - Manages InstantSend locks
 */
class CInstantSendManager
{
private:
    mutable CCriticalSection cs;
    
    CInstantSendDb db;
    
    // Pending lock requests (txid -> timestamp)
    std::map<uint256, int64_t> pendingRequests;
    
    // Transactions waiting for quorum (txid -> tx)
    std::map<uint256, CTransactionRef> pendingTxs;
    
    // Reference to signing manager
    CSigningManager& signingManager;
    CQuorumManager& quorumManager;
    
    // Our node's proTxHash
    uint256 myProTxHash;
    
public:
    CInstantSendManager(CSigningManager& _signingManager, CQuorumManager& _quorumManager);
    
    // Set our identity
    void SetMyProTxHash(const uint256& _proTxHash) { myProTxHash = _proTxHash; }
    
    // Process a new transaction
    void ProcessTransaction(const CTransactionRef& tx, const CBlockIndex* pindex);
    
    // Try to create a lock for a transaction
    bool TrySignInstantSendLock(const CTransactionRef& tx);
    
    // Process a received lock message
    bool ProcessInstantSendLock(const CInstantSendLock& islock, CValidationState& state);
    
    // Check if a transaction is eligible for InstantSend
    bool IsInstantSendEnabled() const;
    bool CanTxBeLocked(const CTransactionRef& tx) const;
    
    // Check if inputs conflict with existing locks
    bool HasConflictingLock(const CTransaction& tx) const;
    
    // Get lock status for a transaction
    bool IsLocked(const uint256& txid) const;
    bool GetInstantSendLock(const uint256& txid, CInstantSendLock& islockOut) const;
    
    // Mempool integration
    bool CheckCanLock(const CTransaction& tx, bool printDebug = false) const;
    
    // Block validation
    bool ProcessBlock(const CBlock& block, const CBlockIndex* pindex);
    bool UndoBlock(const CBlock& block, const CBlockIndex* pindex);
    
    // Verify a lock signature
    bool VerifyInstantSendLock(const CInstantSendLock& islock) const;
    
    // Get all locks for a set of txids
    std::vector<CInstantSendLock> GetLocksForTxids(const std::vector<uint256>& txids) const;
    
    // Update on new chain tip
    void UpdatedBlockTip(const CBlockIndex* pindex);
    
    // Cleanup expired requests
    void Cleanup();

private:
    // Create the request ID for a transaction
    uint256 CreateRequestId(const std::vector<COutPoint>& inputs) const;
    
    // Sign a lock request
    bool SignLockRequest(const CTransactionRef& tx);
    
    // Check if we should process InstantSend for this tx
    bool ShouldProcessInstantSend(const CTransactionRef& tx) const;
};

// Global instance
extern std::unique_ptr<CInstantSendManager> instantSendManager;

// Initialization
void InitInstantSend(CSigningManager& signingManager, CQuorumManager& quorumManager);
void StopInstantSend();

// Validation helpers
bool CheckInputsForInstantSend(const CTransaction& tx, std::string& strError);

} // namespace llmq

#endif // MYNTA_LLMQ_INSTANTSEND_H

