// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/chainlocks.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "evo/deterministicmns.h"
#include "evo/evodb.h"
#include "hash.h"
#include "util.h"
#include "validation.h"

#include <sstream>

namespace llmq {

// Global instance
std::unique_ptr<CChainLocksManager> chainLocksManager;

// ============================================================================
// Database Key Constants for ChainLock Persistence
// ============================================================================
const std::string CChainLocksDb::DB_CHAINLOCK_BY_HEIGHT = "clsig_h";
const std::string CChainLocksDb::DB_CHAINLOCK_BY_HASH = "clsig_b";
const std::string CChainLocksDb::DB_CHAINLOCK_BEST_HEIGHT = "clsig_best_h";
const std::string CChainLocksDb::DB_CHAINLOCK_BEST_HASH = "clsig_best_b";
const std::string CChainLocksManager::DB_CHAINLOCK_ACTIVATION_HEIGHT = "clsig_activation";

// ============================================================================
// CChainLockSig Implementation
// ============================================================================

uint256 CChainLockSig::GetHash() const
{
    if (!hashCached.load(std::memory_order_acquire)) {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << *this;
        hash = hw.GetHash();
        hashCached.store(true, std::memory_order_release);
    }
    return hash;
}

uint256 CChainLockSig::GetSignHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    // Include genesis block hash for chain binding to prevent cross-chain replay attacks
    hw << Params().GenesisBlock().GetHash();
    hw << static_cast<uint8_t>(CHAINLOCK_QUORUM_TYPE);
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
// CChainLocksDb Implementation (Persistent)
// ============================================================================

CChainLocksDb::CChainLocksDb(CEvoDB& _evoDb)
    : evoDb(_evoDb)
{
}

bool CChainLocksDb::Init()
{
    LOCK(cs);
    
    LogPrintf("CChainLocksDb::%s -- Loading ChainLocks from database...\n", __func__);
    
    // Load best ChainLock height and hash
    evoDb.Read(DB_CHAINLOCK_BEST_HEIGHT, bestChainLockHeight);
    evoDb.Read(DB_CHAINLOCK_BEST_HASH, bestChainLockHash);
    
    // Load all ChainLock signatures from database
    // We iterate through all keys with the clsig_h prefix
    std::unique_ptr<CDBIterator> pcursor(evoDb.GetRawDB().NewIterator());
    pcursor->Seek(std::make_pair(DB_CHAINLOCK_BY_HEIGHT, 0));
    
    int loadedCount = 0;
    while (pcursor->Valid()) {
        std::pair<std::string, int> key;
        if (!pcursor->GetKey(key) || key.first != DB_CHAINLOCK_BY_HEIGHT) {
            break;
        }
        
        CChainLockSig clsig;
        if (pcursor->GetValue(clsig)) {
            locksByHeight[key.second] = clsig;
            locksByHash[clsig.blockHash] = clsig;
            loadedCount++;
        }
        
        pcursor->Next();
    }
    
    LogPrintf("CChainLocksDb::%s -- Loaded %d ChainLocks from database (best height: %d)\n",
              __func__, loadedCount, bestChainLockHeight);
    
    return true;
}

bool CChainLocksDb::Flush()
{
    LOCK(cs);
    
    // Persist best height and hash
    evoDb.Write(DB_CHAINLOCK_BEST_HEIGHT, bestChainLockHeight);
    evoDb.Write(DB_CHAINLOCK_BEST_HASH, bestChainLockHash);
    
    return evoDb.Sync();
}

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
    
    // Store in memory cache
    locksByHeight[clsig.nHeight] = clsig;
    locksByHash[clsig.blockHash] = clsig;
    
    // ====================================================================
    // CRITICAL: Persist to disk immediately for consensus safety
    // This ensures ChainLock protection survives restarts
    // ====================================================================
    evoDb.Write(std::make_pair(DB_CHAINLOCK_BY_HEIGHT, clsig.nHeight), clsig);
    evoDb.Write(std::make_pair(DB_CHAINLOCK_BY_HASH, clsig.blockHash), clsig);
    
    // Update best
    if (clsig.nHeight > bestChainLockHeight) {
        bestChainLockHeight = clsig.nHeight;
        bestChainLockHash = clsig.blockHash;
        
        // Persist best height/hash
        evoDb.Write(DB_CHAINLOCK_BEST_HEIGHT, bestChainLockHeight);
        evoDb.Write(DB_CHAINLOCK_BEST_HASH, bestChainLockHash);
    }
    
    LogPrintf("CChainLocksDb::%s -- Wrote ChainLock to disk: %s\n", __func__, clsig.ToString());
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
            // Remove from disk as well
            evoDb.Erase(std::make_pair(DB_CHAINLOCK_BY_HEIGHT, it->first));
            evoDb.Erase(std::make_pair(DB_CHAINLOCK_BY_HASH, it->second.blockHash));
            
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
        
        // Persist updated best height/hash
        evoDb.Write(DB_CHAINLOCK_BEST_HEIGHT, bestChainLockHeight);
        evoDb.Write(DB_CHAINLOCK_BEST_HASH, bestChainLockHash);
    }
}

// ============================================================================
// CChainLocksManager Implementation (Persistent)
// ============================================================================

CChainLocksManager::CChainLocksManager(
    CEvoDB& _evoDb,
    CSigningManager& _signingManager,
    CQuorumManager& _quorumManager)
    : evoDb(_evoDb)
    , db(_evoDb)
    , signingManager(_signingManager)
    , quorumManager(_quorumManager)
{
}

bool CChainLocksManager::Init()
{
    LOCK(cs);
    
    LogPrintf("CChainLocksManager::%s -- Initializing ChainLocks from database...\n", __func__);
    
    // ====================================================================
    // CRITICAL: Load activation height from disk
    // This ensures ChainLock activation state survives restarts
    // ====================================================================
    int storedActivationHeight = 0;
    if (evoDb.Read(DB_CHAINLOCK_ACTIVATION_HEIGHT, storedActivationHeight)) {
        chainLockActivationHeight = storedActivationHeight;
        LogPrintf("CChainLocksManager::%s -- Loaded ChainLocks activation height from database: %d\n",
                  __func__, chainLockActivationHeight);
    } else {
        LogPrintf("CChainLocksManager::%s -- No stored activation height (ChainLocks not yet activated)\n",
                  __func__);
    }
    
    // Initialize the ChainLocks database (loads all signatures)
    if (!db.Init()) {
        LogPrintf("ERROR: CChainLocksManager::%s -- Failed to initialize ChainLocks database\n", __func__);
        return false;
    }
    
    // Restore best ChainLock from database
    int bestHeight = db.GetBestChainLockHeight();
    if (bestHeight > 0) {
        CChainLockSig clsig;
        if (db.GetChainLock(bestHeight, clsig)) {
            bestChainLock = clsig;
            
            // Try to find the block index
            LOCK(cs_main);
            BlockMap::iterator it = mapBlockIndex.find(clsig.blockHash);
            if (it != mapBlockIndex.end()) {
                bestChainLockBlockIndex = it->second;
            }
        }
    }
    
    LogPrintf("CChainLocksManager::%s -- ChainLocks initialized (activation: %d, best lock: %d)\n",
              __func__, chainLockActivationHeight, db.GetBestChainLockHeight());
    
    return true;
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
    
    // Use conditional activation check instead of static height
    if (!pindex || !IsChainLockActive()) {
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
    BlockMap::iterator it = mapBlockIndex.find(clsig.blockHash);
    const CBlockIndex* pindex = (it != mapBlockIndex.end()) ? it->second : nullptr;
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
    LOCK(cs);
    return chainLockActivationHeight > 0;
}

// ============================================================
// CONDITIONAL ACTIVATION IMPLEMENTATION
// All methods derive state from chain data only.
// ============================================================

int CChainLocksManager::GetActivationHeight() const
{
    LOCK(cs);
    return chainLockActivationHeight;
}

int CChainLocksManager::GetNextActivationAttemptHeight() const
{
    LOCK(cs);
    
    // Already activated - no next attempt
    if (chainLockActivationHeight > 0) {
        return 0;
    }
    
    LOCK(cs_main);
    int currentHeight = chainActive.Height();
    
    // Before minimum height
    if (currentHeight < CHAINLOCK_MIN_ACTIVATION_HEIGHT) {
        // First attempt is at the first interval boundary >= min height
        int firstAttempt = ((CHAINLOCK_MIN_ACTIVATION_HEIGHT / CHAINLOCK_ACTIVATION_INTERVAL) + 1) 
                          * CHAINLOCK_ACTIVATION_INTERVAL;
        return firstAttempt;
    }
    
    // Find next interval boundary
    int currentInterval = currentHeight / CHAINLOCK_ACTIVATION_INTERVAL;
    int nextInterval = (currentInterval + 1) * CHAINLOCK_ACTIVATION_INTERVAL;
    return nextInterval;
}

int CChainLocksManager::GetEligibleMasternodeCount() const
{
    LOCK(cs_main);
    
    if (!deterministicMNManager) {
        return 0;
    }
    
    auto mnList = deterministicMNManager->GetListAtChainTip();
    if (!mnList) {
        return 0;
    }
    
    // Count PoSe-valid masternodes with valid operator keys
    int count = 0;
    mnList->ForEachMN(true, [&](const CDeterministicMNCPtr& mn) {
        // Only count if has valid operator key (required for quorum participation)
        if (!mn->state.vchOperatorPubKey.empty()) {
            count++;
        }
    });
    
    return count;
}

ChainLockActivationReason CChainLocksManager::GetActivationStatus() const
{
    LOCK(cs);
    
    // Already activated
    if (chainLockActivationHeight > 0) {
        return ChainLockActivationReason::ENABLED;
    }
    
    LOCK(cs_main);
    int currentHeight = chainActive.Height();
    
    // Before minimum height
    if (currentHeight < CHAINLOCK_MIN_ACTIVATION_HEIGHT) {
        return ChainLockActivationReason::BEFORE_MIN_HEIGHT;
    }
    
    // Check if we're at an activation boundary
    bool atBoundary = (currentHeight % CHAINLOCK_ACTIVATION_INTERVAL == 0) &&
                      (currentHeight >= CHAINLOCK_MIN_ACTIVATION_HEIGHT);
    
    if (!atBoundary) {
        return ChainLockActivationReason::WAITING_NEXT_INTERVAL;
    }
    
    // Check masternode count
    int mnCount = GetEligibleMasternodeCount();
    if (mnCount < CHAINLOCK_REQUIRED_MASTERNODES) {
        return ChainLockActivationReason::INSUFFICIENT_MASTERNODES;
    }
    
    // Check for valid quorum
    auto quorums = quorumManager.GetActiveQuorums(CHAINLOCK_QUORUM_TYPE);
    bool hasValidQuorum = false;
    for (const auto& quorum : quorums) {
        if (quorum && quorum->IsValid()) {
            hasValidQuorum = true;
            break;
        }
    }
    
    if (!hasValidQuorum) {
        return ChainLockActivationReason::NO_VALID_QUORUM;
    }
    
    // All conditions met but not yet activated (should activate on this block)
    return ChainLockActivationReason::ENABLED;
}

bool CChainLocksManager::ShouldAttemptActivation(int nHeight) const
{
    // Already activated
    {
        LOCK(cs);
        if (chainLockActivationHeight > 0) {
            return false;
        }
    }
    
    // Before minimum height
    if (nHeight < CHAINLOCK_MIN_ACTIVATION_HEIGHT) {
        return false;
    }
    
    // Only at interval boundaries
    return (nHeight % CHAINLOCK_ACTIVATION_INTERVAL == 0);
}

bool CChainLocksManager::TryActivate(int nHeight)
{
    if (!ShouldAttemptActivation(nHeight)) {
        return false;
    }
    
    LOCK(cs);
    
    // Double-check not already activated
    if (chainLockActivationHeight > 0) {
        return true;
    }
    
    // Check masternode count
    int mnCount = GetEligibleMasternodeCount();
    if (mnCount < CHAINLOCK_REQUIRED_MASTERNODES) {
        LogPrintf("CChainLocksManager::%s -- Activation deferred at height %d: "
                  "insufficient masternodes (%d < %d)\n",
                  __func__, nHeight, mnCount, CHAINLOCK_REQUIRED_MASTERNODES);
        return false;
    }
    
    // Check for valid quorum
    auto quorums = quorumManager.GetActiveQuorums(CHAINLOCK_QUORUM_TYPE);
    bool hasValidQuorum = false;
    for (const auto& quorum : quorums) {
        if (quorum && quorum->IsValid()) {
            hasValidQuorum = true;
            break;
        }
    }
    
    if (!hasValidQuorum) {
        LogPrintf("CChainLocksManager::%s -- Activation deferred at height %d: "
                  "no valid quorum available\n",
                  __func__, nHeight);
        return false;
    }
    
    // Activate!
    chainLockActivationHeight = nHeight;
    
    // ====================================================================
    // CRITICAL: Persist activation height to disk immediately
    // This ensures activation state survives restarts
    // ====================================================================
    evoDb.Write(DB_CHAINLOCK_ACTIVATION_HEIGHT, chainLockActivationHeight);
    
    LogPrintf("CChainLocksManager::%s -- ChainLocks ACTIVATED at height %d "
              "(masternodes: %d, required: %d) - PERSISTED TO DISK\n",
              __func__, nHeight, mnCount, CHAINLOCK_REQUIRED_MASTERNODES);
    
    return true;
}

void CChainLocksManager::SetActivationHeight(int nHeight)
{
    LOCK(cs);
    chainLockActivationHeight = nHeight;
    
    // Persist to disk
    if (nHeight > 0) {
        evoDb.Write(DB_CHAINLOCK_ACTIVATION_HEIGHT, nHeight);
        LogPrintf("CChainLocksManager::%s -- ChainLocks activation height set to %d (persisted)\n",
                  __func__, nHeight);
    } else {
        evoDb.Erase(DB_CHAINLOCK_ACTIVATION_HEIGHT);
        LogPrintf("CChainLocksManager::%s -- ChainLocks activation height cleared\n", __func__);
    }
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
    
    LOCK(cs_main);
    const auto& cp = GetParams().GetConsensus();
    const CBlockIndex* pindex;
    if (clsig.nHeight >= cp.nConsensusFixHeight) {
        pindex = chainActive[clsig.nHeight];
    } else {
        pindex = chainActive[clsig.nHeight - 1];
    }
    if (!pindex) {
        pindex = chainActive.Tip();
    }
    
    auto quorum = quorumManager.SelectQuorumForSigning(
        CHAINLOCK_QUORUM_TYPE, pindex, clsig.GetRequestId());
    
    if (!quorum || !quorum->IsValid()) {
        LogPrintf("CChainLocksManager::%s -- No valid quorum for ChainLock\n", __func__);
        return false;
    }
    
    // Verify the signature with domain separation
    uint256 signHash = clsig.GetSignHash();
    if (!clsig.sig.VerifyWithDomain(quorum->quorumPublicKey, signHash, BLSDomainTags::QUORUM)) {
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
    if (!pindex) return;
    
    // ============================================================
    // CONDITIONAL ACTIVATION CHECK
    // Attempt activation at interval boundaries. This is called
    // during block processing and produces deterministic results.
    // ============================================================
    if (ShouldAttemptActivation(pindex->nHeight)) {
        TryActivate(pindex->nHeight);
    }
    
    LOCK(cs);
    
    // Process any pending ChainLocks for blocks we now have
    for (auto it = pendingChainLocks.begin(); it != pendingChainLocks.end(); ) {
        LOCK(cs_main);
        BlockMap::iterator blockIt = mapBlockIndex.find(it->second.blockHash);
        const CBlockIndex* blockIndex = (blockIt != mapBlockIndex.end()) ? blockIt->second : nullptr;
        if (blockIndex && blockIndex->nHeight == it->second.nHeight) {
            CValidationState state;
            ProcessChainLock(it->second, state);
            it = pendingChainLocks.erase(it);
        } else {
            ++it;
        }
    }
    
    // Try to sign new tip (only if ChainLocks are activated)
    if (IsChainLockActive()) {
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
    return IsChainLockActive();
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

void InitChainLocks(CEvoDB& evoDb, CSigningManager& signingManager, CQuorumManager& quorumManager)
{
    chainLocksManager = std::make_unique<CChainLocksManager>(evoDb, signingManager, quorumManager);
    
    // ====================================================================
    // CRITICAL: Initialize from database - loads activation height and 
    // all ChainLock signatures from disk
    // ====================================================================
    if (!chainLocksManager->Init()) {
        LogPrintf("ERROR: Failed to initialize ChainLocks from database\n");
        // Continue anyway - will rebuild state from chain
    }
    
    LogPrintf("ChainLocks initialized with persistence\n");
}

void StopChainLocks()
{
    if (chainLocksManager) {
        // Flush any pending changes before shutdown
        // (Note: Most changes are persisted immediately, but this ensures consistency)
        LogPrintf("ChainLocks stopping - flushing to disk...\n");
    }
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
    
    // ====================================================================
    // CRITICAL FIX: Actually check if block conflicts with ChainLock
    // 
    // If we have a ChainLock at this height for a DIFFERENT block hash,
    // this block must be rejected. This provides defense-in-depth beyond
    // just the fork-choice rules in CanReorg().
    // ====================================================================
    
    // Check if there's a ChainLock at this height
    if (chainLocksManager->IsChainLocked(pindex->nHeight)) {
        // Get the ChainLock and verify hash matches
        CChainLockSig clsig = chainLocksManager->GetBestChainLock();
        
        // If best ChainLock is at or above this height, check the chain
        if (clsig.nHeight >= pindex->nHeight) {
            // For blocks at the ChainLock height, hash must match exactly
            if (clsig.nHeight == pindex->nHeight && 
                clsig.blockHash != pindex->GetBlockHash()) {
                LogPrintf("CheckAgainstChainLocks: REJECTING block %s at height %d - "
                          "conflicts with ChainLocked block %s\n",
                          pindex->GetBlockHash().ToString().substr(0, 16),
                          pindex->nHeight,
                          clsig.blockHash.ToString().substr(0, 16));
                
                return state.DoS(100, false, REJECT_INVALID, "chainlock-conflict",
                               false, "Block conflicts with ChainLock at same height");
            }
            
            // For blocks below ChainLock height, verify this block is on the locked chain
            if (clsig.nHeight > pindex->nHeight) {
                LOCK(cs_main);
                BlockMap::iterator it = mapBlockIndex.find(clsig.blockHash);
                const CBlockIndex* pClockBlock = (it != mapBlockIndex.end()) ? it->second : nullptr;
                if (pClockBlock) {
                    const CBlockIndex* pAncestor = pClockBlock->GetAncestor(pindex->nHeight);
                    if (pAncestor && pAncestor->GetBlockHash() != pindex->GetBlockHash()) {
                        LogPrintf("CheckAgainstChainLocks: REJECTING block %s at height %d - "
                                  "not on ChainLocked chain (expected %s)\n",
                                  pindex->GetBlockHash().ToString().substr(0, 16),
                                  pindex->nHeight,
                                  pAncestor->GetBlockHash().ToString().substr(0, 16));
                        
                        return state.DoS(100, false, REJECT_INVALID, "chainlock-ancestor-conflict",
                                       false, "Block not on ChainLocked chain");
                    }
                }
            }
        }
    }
    
    return true;
}

} // namespace llmq

