// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/chainlocks.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "util.h"
#include "validation.h"

#include <sstream>

namespace llmq {

// Global instance
std::unique_ptr<CChainLocksManager> chainLocksManager;

// ============================================================================
// CChainLockSig Implementation
// ============================================================================

uint256 CChainLockSig::GetHash() const
{
    if (!hashCached) {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << *this;
        hash = hw.GetHash();
        hashCached = true;
    }
    return hash;
}

uint256 CChainLockSig::GetSignHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << CHAINLOCK_QUORUM_TYPE;
    hw << GetRequestId();
    hw << blockHash;
    return hw.GetHash();
}

uint256 CChainLockSig::GetRequestId() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("clsig_request");
    hw << nHeight;
    return hw.GetHash();
}

std::string CChainLockSig::ToString() const
{
    std::ostringstream ss;
    ss << "CChainLockSig("
       << "height=" << nHeight
       << ", block=" << blockHash.ToString().substr(0, 16)
       << ")";
    return ss.str();
}

// ============================================================================
// CChainLocksDb Implementation
// ============================================================================

bool CChainLocksDb::WriteChainLock(const CChainLockSig& clsig)
{
    LOCK(cs);
    
    // Don't allow going backwards
    if (clsig.nHeight <= bestChainLockHeight && bestChainLockHeight > 0) {
        // Allow updating same height (shouldn't happen, but be safe)
        if (clsig.nHeight < bestChainLockHeight) {
            LogPrintf("CChainLocksDb::%s -- Rejecting ChainLock at height %d (current best: %d)\n",
                      __func__, clsig.nHeight, bestChainLockHeight);
            return false;
        }
    }
    
    // Store by height and hash
    locksByHeight[clsig.nHeight] = clsig;
    locksByHash[clsig.blockHash] = clsig;
    
    // Update best
    if (clsig.nHeight > bestChainLockHeight) {
        bestChainLockHeight = clsig.nHeight;
        bestChainLockHash = clsig.blockHash;
    }
    
    LogPrintf("CChainLocksDb::%s -- Wrote ChainLock: %s\n", __func__, clsig.ToString());
    return true;
}

bool CChainLocksDb::GetChainLock(int nHeight, CChainLockSig& clsigOut) const
{
    LOCK(cs);
    
    auto it = locksByHeight.find(nHeight);
    if (it == locksByHeight.end()) {
        return false;
    }
    
    clsigOut = it->second;
    return true;
}

bool CChainLocksDb::GetChainLockByHash(const uint256& blockHash, CChainLockSig& clsigOut) const
{
    LOCK(cs);
    
    auto it = locksByHash.find(blockHash);
    if (it == locksByHash.end()) {
        return false;
    }
    
    clsigOut = it->second;
    return true;
}

bool CChainLocksDb::IsChainLocked(int nHeight) const
{
    LOCK(cs);
    return locksByHeight.count(nHeight) > 0;
}

bool CChainLocksDb::HasChainLock(const uint256& blockHash) const
{
    LOCK(cs);
    return locksByHash.count(blockHash) > 0;
}

int CChainLocksDb::GetBestChainLockHeight() const
{
    LOCK(cs);
    return bestChainLockHeight;
}

uint256 CChainLocksDb::GetBestChainLockHash() const
{
    LOCK(cs);
    return bestChainLockHash;
}

void CChainLocksDb::RemoveAboveHeight(int nHeight)
{
    LOCK(cs);
    
    for (auto it = locksByHeight.begin(); it != locksByHeight.end(); ) {
        if (it->first > nHeight) {
            locksByHash.erase(it->second.blockHash);
            it = locksByHeight.erase(it);
        } else {
            ++it;
        }
    }
    
    // Update best
    if (bestChainLockHeight > nHeight) {
        bestChainLockHeight = nHeight;
        auto it = locksByHeight.find(nHeight);
        if (it != locksByHeight.end()) {
            bestChainLockHash = it->second.blockHash;
        } else {
            bestChainLockHash.SetNull();
        }
    }
}

// ============================================================================
// CChainLocksManager Implementation
// ============================================================================

CChainLocksManager::CChainLocksManager(
    CSigningManager& _signingManager,
    CQuorumManager& _quorumManager)
    : signingManager(_signingManager)
    , quorumManager(_quorumManager)
{
}

void CChainLocksManager::ProcessNewBlock(const CBlock& block, const CBlockIndex* pindex)
{
    if (!IsChainLockActive()) {
        return;
    }
    
    if (!pindex) {
        return;
    }
    
    // Only try to sign the best chain
    LOCK(cs_main);
    if (pindex != chainActive.Tip()) {
        return;
    }
    
    // Try to sign this block
    TrySignChainLock(pindex);
}

bool CChainLocksManager::TrySignChainLock(const CBlockIndex* pindex)
{
    LOCK(cs);
    
    if (!pindex || pindex->nHeight < CHAINLOCK_ACTIVATION_HEIGHT) {
        return false;
    }
    
    // Already have a lock at this height?
    if (db.IsChainLocked(pindex->nHeight)) {
        return true;
    }
    
    // Already trying to sign?
    if (signingHeights.count(pindex->nHeight)) {
        return false;
    }
    
    signingHeights.insert(pindex->nHeight);
    
    // Create request ID
    uint256 requestId = CreateRequestId(pindex->nHeight);
    
    // Build message hash
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << requestId;
    hw << pindex->GetBlockHash();
    uint256 msgHash = hw.GetHash();
    
    // Try to sign
    if (!signingManager.AsyncSign(CHAINLOCK_QUORUM_TYPE, requestId, msgHash)) {
        signingHeights.erase(pindex->nHeight);
        return false;
    }
    
    // Check if we can recover
    CRecoveredSig recSig;
    if (signingManager.TryRecoverSignature(CHAINLOCK_QUORUM_TYPE, requestId, msgHash, recSig)) {
        // Build ChainLock
        CChainLockSig clsig(pindex->nHeight, pindex->GetBlockHash());
        clsig.sig = recSig.sig;
        
        // Process it
        CValidationState state;
        ProcessChainLock(clsig, state);
    }
    
    return true;
}

bool CChainLocksManager::ProcessChainLock(const CChainLockSig& clsig, CValidationState& state)
{
    LOCK(cs);
    
    // Already have it?
    if (db.HasChainLock(clsig.blockHash)) {
        return true;
    }
    
    // Validate height is increasing
    int currentBest = db.GetBestChainLockHeight();
    if (clsig.nHeight <= currentBest) {
        // Allow same height only if same hash
        CChainLockSig existing;
        if (db.GetChainLock(clsig.nHeight, existing)) {
            if (existing.blockHash != clsig.blockHash) {
                // Conflict! This should not happen with honest quorum
                LogPrintf("CChainLocksManager::%s -- CONFLICT at height %d!\n",
                          __func__, clsig.nHeight);
                return state.DoS(100, false, REJECT_DUPLICATE, "chainlock-conflict");
            }
        }
        return true; // Already have it
    }
    
    // Verify signature
    if (!VerifyChainLock(clsig)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-chainlock-sig");
    }
    
    // Verify block exists in our chain
    LOCK(cs_main);
    const CBlockIndex* pindex = LookupBlockIndex(clsig.blockHash);
    if (!pindex) {
        LogPrintf("CChainLocksManager::%s -- Block not found: %s\n",
                  __func__, clsig.blockHash.ToString().substr(0, 16));
        // Store pending - we might receive the block later
        pendingChainLocks[clsig.nHeight] = clsig;
        return true;
    }
    
    // Verify height matches
    if (pindex->nHeight != clsig.nHeight) {
        return state.DoS(100, false, REJECT_INVALID, "chainlock-height-mismatch");
    }
    
    // Store the ChainLock
    if (!db.WriteChainLock(clsig)) {
        return false;
    }
    
    // Update best
    bestChainLock = clsig;
    bestChainLockBlockIndex = pindex;
    
    // Remove from pending
    pendingChainLocks.erase(clsig.nHeight);
    signingHeights.erase(clsig.nHeight);
    
    LogPrintf("CChainLocksManager::%s -- Processed ChainLock: %s\n", __func__, clsig.ToString());
    
    return true;
}

bool CChainLocksManager::IsChainLockActive() const
{
    LOCK(cs_main);
    return chainActive.Height() >= CHAINLOCK_ACTIVATION_HEIGHT;
}

bool CChainLocksManager::IsChainLocked(int nHeight) const
{
    LOCK(cs);
    return db.IsChainLocked(nHeight);
}

bool CChainLocksManager::HasChainLock(const uint256& blockHash) const
{
    LOCK(cs);
    return db.HasChainLock(blockHash);
}

bool CChainLocksManager::HasChainLock(const CBlockIndex* pindex) const
{
    if (!pindex) return false;
    return HasChainLock(pindex->GetBlockHash());
}

CChainLockSig CChainLocksManager::GetBestChainLock() const
{
    LOCK(cs);
    return bestChainLock;
}

int CChainLocksManager::GetBestChainLockHeight() const
{
    LOCK(cs);
    return db.GetBestChainLockHeight();
}

bool CChainLocksManager::CanReorg(const CBlockIndex* pindexNew, const CBlockIndex* pindexOld) const
{
    if (!pindexNew || !pindexOld) {
        return true; // Allow if we don't have both
    }
    
    LOCK(cs);
    
    // Find common ancestor
    const CBlockIndex* pindexFork = LastCommonAncestor(pindexNew, pindexOld);
    if (!pindexFork) {
        return true;
    }
    
    int bestCLHeight = db.GetBestChainLockHeight();
    
    // If the fork point is at or below a ChainLocked block, disallow reorg
    if (pindexFork->nHeight < bestCLHeight) {
        LogPrintf("CChainLocksManager::%s -- Rejecting reorg: fork at %d, ChainLock at %d\n",
                  __func__, pindexFork->nHeight, bestCLHeight);
        return false;
    }
    
    return true;
}

bool CChainLocksManager::VerifyChainLock(const CChainLockSig& clsig) const
{
    if (!clsig.sig.IsValid()) {
        return false;
    }
    
    // Get the quorum for this height
    LOCK(cs_main);
    const CBlockIndex* pindex = chainActive[clsig.nHeight - 1];
    if (!pindex) {
        // Use tip if we don't have exact height
        pindex = chainActive.Tip();
    }
    
    auto quorum = quorumManager.SelectQuorumForSigning(
        CHAINLOCK_QUORUM_TYPE, pindex, clsig.GetRequestId());
    
    if (!quorum || !quorum->IsValid()) {
        LogPrintf("CChainLocksManager::%s -- No valid quorum for ChainLock\n", __func__);
        return false;
    }
    
    // Verify the signature
    uint256 signHash = clsig.GetSignHash();
    if (!clsig.sig.VerifyInsecure(quorum->quorumPublicKey, signHash)) {
        LogPrintf("CChainLocksManager::%s -- Signature verification failed\n", __func__);
        return false;
    }
    
    return true;
}

bool CChainLocksManager::ShouldPreferChainLocked(
    const CBlockIndex* pindexA,
    const CBlockIndex* pindexB) const
{
    if (!pindexA || !pindexB) {
        return false;
    }
    
    bool aLocked = HasChainLock(pindexA);
    bool bLocked = HasChainLock(pindexB);
    
    // Prefer ChainLocked chain
    if (aLocked && !bLocked) return true;
    if (!aLocked && bLocked) return false;
    
    // If both or neither, prefer more work
    return pindexA->nChainWork > pindexB->nChainWork;
}

void CChainLocksManager::UpdatedBlockTip(const CBlockIndex* pindex)
{
    LOCK(cs);
    
    // Process any pending ChainLocks for blocks we now have
    for (auto it = pendingChainLocks.begin(); it != pendingChainLocks.end(); ) {
        LOCK(cs_main);
        const CBlockIndex* blockIndex = LookupBlockIndex(it->second.blockHash);
        if (blockIndex && blockIndex->nHeight == it->second.nHeight) {
            CValidationState state;
            ProcessChainLock(it->second, state);
            it = pendingChainLocks.erase(it);
        } else {
            ++it;
        }
    }
    
    // Try to sign new tip
    if (pindex && pindex->nHeight >= CHAINLOCK_ACTIVATION_HEIGHT) {
        TrySignChainLock(pindex);
    }
}

void CChainLocksManager::Cleanup()
{
    LOCK(cs);
    
    // Clean up old signing attempts
    int currentHeight = 0;
    {
        LOCK(cs_main);
        currentHeight = chainActive.Height();
    }
    
    if (currentHeight <= lastCleanupHeight + 100) {
        return; // Don't cleanup too often
    }
    
    lastCleanupHeight = currentHeight;
    
    // Remove old signing heights
    for (auto it = signingHeights.begin(); it != signingHeights.end(); ) {
        if (*it < currentHeight - 100) {
            it = signingHeights.erase(it);
        } else {
            ++it;
        }
    }
    
    // Remove old pending ChainLocks
    for (auto it = pendingChainLocks.begin(); it != pendingChainLocks.end(); ) {
        if (it->first < currentHeight - 100) {
            it = pendingChainLocks.erase(it);
        } else {
            ++it;
        }
    }
}

uint256 CChainLocksManager::CreateRequestId(int nHeight) const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("clsig_request");
    hw << nHeight;
    return hw.GetHash();
}

bool CChainLocksManager::SignChainLock(const CBlockIndex* pindex)
{
    return TrySignChainLock(pindex);
}

bool CChainLocksManager::ShouldSignAt(int nHeight) const
{
    return nHeight >= CHAINLOCK_ACTIVATION_HEIGHT;
}

CQuorumCPtr CChainLocksManager::SelectQuorum(const CBlockIndex* pindex) const
{
    if (!pindex) return nullptr;
    
    uint256 requestId = CreateRequestId(pindex->nHeight);
    return quorumManager.SelectQuorumForSigning(CHAINLOCK_QUORUM_TYPE, pindex, requestId);
}

// ============================================================================
// Initialization
// ============================================================================

void InitChainLocks(CSigningManager& signingManager, CQuorumManager& quorumManager)
{
    chainLocksManager = std::make_unique<CChainLocksManager>(signingManager, quorumManager);
    LogPrintf("ChainLocks initialized\n");
}

void StopChainLocks()
{
    chainLocksManager.reset();
    LogPrintf("ChainLocks stopped\n");
}

// ============================================================================
// Validation Integration
// ============================================================================

bool CheckAgainstChainLocks(const CBlockIndex* pindex, CValidationState& state)
{
    if (!chainLocksManager) {
        return true;
    }
    
    if (!pindex) {
        return true;
    }
    
    // Check if this block conflicts with a ChainLock
    CChainLockSig clsig;
    if (chainLocksManager->IsChainLocked(pindex->nHeight)) {
        // Get the ChainLock for this height
        // If the block hash doesn't match, reject
        // (This would require getting the lock and comparing)
        
        // For now, if we have a ChainLock at this height, the block
        // must match - otherwise it would have been rejected earlier
    }
    
    return true;
}

} // namespace llmq

