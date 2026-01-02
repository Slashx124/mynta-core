// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/instantsend.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "net.h"
#include "txmempool.h"
#include "util.h"
#include "validation.h"

#include <sstream>

namespace llmq {

// Global instance
std::unique_ptr<CInstantSendManager> instantSendManager;

// ============================================================================
// CInstantSendLock Implementation
// ============================================================================

uint256 CInstantSendLock::GetHash() const
{
    if (!hashCached) {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << *this;
        hash = hw.GetHash();
        hashCached = true;
    }
    return hash;
}

uint256 CInstantSendLock::GetRequestId() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("islock_request");
    for (const auto& input : inputs) {
        hw << input;
    }
    return hw.GetHash();
}

uint256 CInstantSendLock::GetSignHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << static_cast<uint8_t>(INSTANTSEND_QUORUM_TYPE);
    hw << quorumHash;
    hw << GetRequestId();
    hw << txid;
    return hw.GetHash();
}

std::string CInstantSendLock::ToString() const
{
    std::ostringstream ss;
    ss << "CInstantSendLock("
       << "txid=" << txid.ToString().substr(0, 16)
       << ", inputs=" << inputs.size()
       << ", quorum=" << quorumHash.ToString().substr(0, 16)
       << ")";
    return ss.str();
}

// ============================================================================
// CInstantSendDb Implementation
// ============================================================================

bool CInstantSendDb::WriteLock(const CInstantSendLock& islock)
{
    LOCK(cs);
    
    uint256 hash = islock.GetHash();
    
    // Store lock
    locksById[hash] = islock;
    txidToLockHash[islock.txid] = hash;
    
    // Index inputs
    for (const auto& input : islock.inputs) {
        inputLocks[input] = hash;
    }
    
    LogPrintf("CInstantSendDb::%s -- Wrote lock: %s\n", __func__, islock.ToString());
    return true;
}

bool CInstantSendDb::GetLock(const uint256& hash, CInstantSendLock& islockOut) const
{
    LOCK(cs);
    
    auto it = locksById.find(hash);
    if (it == locksById.end()) {
        return false;
    }
    
    islockOut = it->second;
    return true;
}

bool CInstantSendDb::GetLockByTxid(const uint256& txid, CInstantSendLock& islockOut) const
{
    LOCK(cs);
    
    auto it = txidToLockHash.find(txid);
    if (it == txidToLockHash.end()) {
        return false;
    }
    
    return GetLock(it->second, islockOut);
}

bool CInstantSendDb::IsInputLocked(const COutPoint& outpoint) const
{
    LOCK(cs);
    return inputLocks.count(outpoint) > 0;
}

bool CInstantSendDb::IsTxLocked(const uint256& txid) const
{
    LOCK(cs);
    return txidToLockHash.count(txid) > 0;
}

bool CInstantSendDb::GetLockForInput(const COutPoint& outpoint, CInstantSendLock& islockOut) const
{
    LOCK(cs);
    
    auto it = inputLocks.find(outpoint);
    if (it == inputLocks.end()) {
        return false;
    }
    
    return GetLock(it->second, islockOut);
}

void CInstantSendDb::RemoveLock(const uint256& hash)
{
    LOCK(cs);
    
    auto it = locksById.find(hash);
    if (it == locksById.end()) {
        return;
    }
    
    const CInstantSendLock& islock = it->second;
    
    // Remove input index
    for (const auto& input : islock.inputs) {
        inputLocks.erase(input);
    }
    
    // Remove txid mapping
    txidToLockHash.erase(islock.txid);
    
    // Remove lock
    locksById.erase(it);
    
    LogPrintf("CInstantSendDb::%s -- Removed lock: %s\n", __func__, hash.ToString().substr(0, 16));
}

void CInstantSendDb::RemoveLocksForTxids(const std::set<uint256>& txids)
{
    LOCK(cs);
    
    for (const auto& txid : txids) {
        auto it = txidToLockHash.find(txid);
        if (it != txidToLockHash.end()) {
            RemoveLock(it->second);
        }
    }
}

std::set<COutPoint> CInstantSendDb::GetAllLockedOutpoints() const
{
    LOCK(cs);
    
    std::set<COutPoint> result;
    for (const auto& [outpoint, hash] : inputLocks) {
        result.insert(outpoint);
    }
    return result;
}

// ============================================================================
// CInstantSendManager Implementation
// ============================================================================

CInstantSendManager::CInstantSendManager(
    CSigningManager& _signingManager,
    CQuorumManager& _quorumManager)
    : signingManager(_signingManager)
    , quorumManager(_quorumManager)
{
}

void CInstantSendManager::ProcessTransaction(const CTransactionRef& tx, const CBlockIndex* pindex)
{
    if (!IsInstantSendEnabled()) {
        return;
    }
    
    if (!CanTxBeLocked(tx)) {
        return;
    }
    
    if (HasConflictingLock(*tx)) {
        LogPrintf("CInstantSendManager::%s -- TX %s has conflicting lock\n",
                  __func__, tx->GetHash().ToString().substr(0, 16));
        return;
    }
    
    // Add to pending
    {
        LOCK(cs);
        pendingTxs[tx->GetHash()] = tx;
        pendingRequests[tx->GetHash()] = GetTime();
    }
    
    // Try to sign
    TrySignInstantSendLock(tx);
}

bool CInstantSendManager::TrySignInstantSendLock(const CTransactionRef& tx)
{
    LOCK(cs);
    
    if (myProTxHash.IsNull()) {
        return false;
    }
    
    // Build request ID from inputs
    std::vector<COutPoint> inputs;
    for (const auto& txin : tx->vin) {
        inputs.push_back(txin.prevout);
    }
    
    uint256 requestId = CreateRequestId(inputs);
    
    // Build message hash
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << requestId;
    hw << tx->GetHash();
    uint256 msgHash = hw.GetHash();
    
    // Try to sign
    if (!signingManager.AsyncSign(INSTANTSEND_QUORUM_TYPE, requestId, msgHash)) {
        return false;
    }
    
    // Check if we can recover a signature
    CRecoveredSig recSig;
    if (signingManager.TryRecoverSignature(INSTANTSEND_QUORUM_TYPE, requestId, msgHash, recSig)) {
        // Build InstantSend lock
        CInstantSendLock islock;
        islock.inputs = inputs;
        islock.txid = tx->GetHash();
        islock.quorumHash = recSig.quorumHash;
        islock.sig = recSig.sig;
        
        // Process it
        CValidationState state;
        ProcessInstantSendLock(islock, state);
    }
    
    return true;
}

bool CInstantSendManager::ProcessInstantSendLock(const CInstantSendLock& islock, CValidationState& state)
{
    LOCK(cs);
    
    // Already have it?
    if (db.IsTxLocked(islock.txid)) {
        return true;
    }
    
    // Verify signature
    if (!VerifyInstantSendLock(islock)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-islock-sig");
    }
    
    // Check for conflicts
    for (const auto& input : islock.inputs) {
        if (db.IsInputLocked(input)) {
            CInstantSendLock existingLock;
            if (db.GetLockForInput(input, existingLock)) {
                if (existingLock.txid != islock.txid) {
                    // Conflict! This should not happen with honest quorum
                    LogPrintf("CInstantSendManager::%s -- CONFLICT! Input already locked by different TX\n", __func__);
                    return state.DoS(100, false, REJECT_DUPLICATE, "islock-conflict");
                }
            }
        }
    }
    
    // Store the lock
    if (!db.WriteLock(islock)) {
        return false;
    }
    
    // Remove from pending
    pendingTxs.erase(islock.txid);
    pendingRequests.erase(islock.txid);
    
    LogPrintf("CInstantSendManager::%s -- Processed lock: %s\n", __func__, islock.ToString());
    
    return true;
}

bool CInstantSendManager::IsInstantSendEnabled() const
{
    // Check if we have active quorums
    LOCK(cs_main);
    auto quorums = quorumManager.GetActiveQuorums(INSTANTSEND_QUORUM_TYPE);
    return !quorums.empty();
}

bool CInstantSendManager::CanTxBeLocked(const CTransactionRef& tx) const
{
    if (!tx) {
        return false;
    }
    
    // Coinbase cannot be instant
    if (tx->IsCoinBase()) {
        return false;
    }
    
    // Too many inputs
    if (tx->vin.size() > INSTANTSEND_MAX_INPUTS) {
        return false;
    }
    
    // All inputs must have at least 1 confirmation
    // (This check would need UTXO access in production)
    
    return true;
}

bool CInstantSendManager::HasConflictingLock(const CTransaction& tx) const
{
    LOCK(cs);
    
    for (const auto& txin : tx.vin) {
        if (db.IsInputLocked(txin.prevout)) {
            CInstantSendLock existingLock;
            if (db.GetLockForInput(txin.prevout, existingLock)) {
                if (existingLock.txid != tx.GetHash()) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

bool CInstantSendManager::IsLocked(const uint256& txid) const
{
    LOCK(cs);
    return db.IsTxLocked(txid);
}

bool CInstantSendManager::GetInstantSendLock(const uint256& txid, CInstantSendLock& islockOut) const
{
    LOCK(cs);
    return db.GetLockByTxid(txid, islockOut);
}

bool CInstantSendManager::CheckCanLock(const CTransaction& tx, bool printDebug) const
{
    if (!IsInstantSendEnabled()) {
        if (printDebug) {
            LogPrintf("CInstantSendManager::%s -- InstantSend not enabled\n", __func__);
        }
        return false;
    }
    
    if (tx.IsCoinBase()) {
        return false;
    }
    
    if (tx.vin.size() > INSTANTSEND_MAX_INPUTS) {
        if (printDebug) {
            LogPrintf("CInstantSendManager::%s -- Too many inputs (%d > %d)\n",
                      __func__, tx.vin.size(), INSTANTSEND_MAX_INPUTS);
        }
        return false;
    }
    
    if (HasConflictingLock(tx)) {
        if (printDebug) {
            LogPrintf("CInstantSendManager::%s -- Has conflicting lock\n", __func__);
        }
        return false;
    }
    
    return true;
}

bool CInstantSendManager::ProcessBlock(const CBlock& block, const CBlockIndex* pindex)
{
    LOCK(cs);
    
    // Remove pending requests for included transactions
    for (const auto& tx : block.vtx) {
        pendingTxs.erase(tx->GetHash());
        pendingRequests.erase(tx->GetHash());
    }
    
    return true;
}

bool CInstantSendManager::UndoBlock(const CBlock& block, const CBlockIndex* pindex)
{
    LOCK(cs);
    
    // On reorg, we need to be careful
    // Transactions that were confirmed but are now unconfirmed
    // may still have valid InstantSend locks
    
    // The locks remain valid - they protect against double-spends
    // even during reorgs
    
    return true;
}

bool CInstantSendManager::VerifyInstantSendLock(const CInstantSendLock& islock) const
{
    if (!islock.sig.IsValid()) {
        return false;
    }
    
    // Get the quorum
    auto quorum = quorumManager.GetQuorum(INSTANTSEND_QUORUM_TYPE, islock.quorumHash);
    if (!quorum || !quorum->IsValid()) {
        LogPrintf("CInstantSendManager::%s -- Quorum not found or invalid\n", __func__);
        return false;
    }
    
    // Verify the signature
    uint256 signHash = islock.GetSignHash();
    if (!islock.sig.VerifyInsecure(quorum->quorumPublicKey, signHash)) {
        LogPrintf("CInstantSendManager::%s -- Signature verification failed\n", __func__);
        return false;
    }
    
    return true;
}

std::vector<CInstantSendLock> CInstantSendManager::GetLocksForTxids(const std::vector<uint256>& txids) const
{
    LOCK(cs);
    
    std::vector<CInstantSendLock> result;
    result.reserve(txids.size());
    
    for (const auto& txid : txids) {
        CInstantSendLock islock;
        if (db.GetLockByTxid(txid, islock)) {
            result.push_back(islock);
        }
    }
    
    return result;
}

void CInstantSendManager::UpdatedBlockTip(const CBlockIndex* pindex)
{
    LOCK(cs);
    
    // Retry pending transactions
    for (auto it = pendingTxs.begin(); it != pendingTxs.end(); ) {
        auto& tx = it->second;
        
        // Check if still valid
        if (!CanTxBeLocked(tx) || HasConflictingLock(*tx)) {
            it = pendingTxs.erase(it);
            continue;
        }
        
        // Try signing again
        TrySignInstantSendLock(tx);
        ++it;
    }
}

void CInstantSendManager::Cleanup()
{
    LOCK(cs);
    
    int64_t now = GetTime();
    
    // Remove expired pending requests
    for (auto it = pendingRequests.begin(); it != pendingRequests.end(); ) {
        if (now - it->second > 60) { // 60 second timeout
            pendingTxs.erase(it->first);
            it = pendingRequests.erase(it);
        } else {
            ++it;
        }
    }
}

uint256 CInstantSendManager::CreateRequestId(const std::vector<COutPoint>& inputs) const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("islock_request");
    
    // Sort inputs for determinism
    std::vector<COutPoint> sortedInputs = inputs;
    std::sort(sortedInputs.begin(), sortedInputs.end());
    
    for (const auto& input : sortedInputs) {
        hw << input;
    }
    
    return hw.GetHash();
}

bool CInstantSendManager::SignLockRequest(const CTransactionRef& tx)
{
    return TrySignInstantSendLock(tx);
}

bool CInstantSendManager::ShouldProcessInstantSend(const CTransactionRef& tx) const
{
    if (!IsInstantSendEnabled()) {
        return false;
    }
    
    if (!CanTxBeLocked(tx)) {
        return false;
    }
    
    return true;
}

// ============================================================================
// Initialization
// ============================================================================

void InitInstantSend(CSigningManager& signingManager, CQuorumManager& quorumManager)
{
    instantSendManager = std::make_unique<CInstantSendManager>(signingManager, quorumManager);
    LogPrintf("InstantSend initialized\n");
}

void StopInstantSend()
{
    instantSendManager.reset();
    LogPrintf("InstantSend stopped\n");
}

// ============================================================================
// Validation Helpers
// ============================================================================

bool CheckInputsForInstantSend(const CTransaction& tx, std::string& strError)
{
    if (!instantSendManager) {
        strError = "InstantSend not initialized";
        return false;
    }
    
    if (!instantSendManager->CheckCanLock(tx, true)) {
        strError = "Transaction cannot be locked";
        return false;
    }
    
    if (instantSendManager->HasConflictingLock(tx)) {
        strError = "Conflicting InstantSend lock exists";
        return false;
    }
    
    return true;
}

} // namespace llmq

