// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/quorums.h"
#include "llmq/dkg.h"
#include "llmq/equivocation.h"
#include "llmq/monitoring.h"
#include "chain.h"
#include "chainparams.h"
#include "evo/deterministicmns.h"
#include "hash.h"
#include "support/security_guards.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "validationinterface.h"

#include <algorithm>
#include <sstream>

namespace llmq {

// Global instances
std::unique_ptr<CQuorumManager> quorumManager;
std::unique_ptr<CSigningManager> signingManager;
std::unique_ptr<CLLMQValidationInterface> llmqValidationInterface;

// ============================================================================
// LLMQ Validation Interface
// ============================================================================

class CLLMQValidationInterface : public CValidationInterface
{
protected:
    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) override
    {
        if (fInitialDownload) return;  // Don't process during IBD
        
        if (quorumManager) {
            quorumManager->UpdatedBlockTip(pindexNew);
        }
        
        if (dkgSessionManager) {
            dkgSessionManager->UpdatedBlockTip(pindexNew);
        }
    }
    
    void BlockConnected(const std::shared_ptr<const CBlock>& block, 
                        const CBlockIndex* pindex, 
                        const std::vector<CTransactionRef>& txnConflicted) override
    {
        // Process special transactions in the block for DKG messages
        // This is handled by the DKG manager's message processing
    }
};

// Quorum parameters
static const std::map<LLMQType, LLMQParams> llmqParams = {
    {LLMQType::LLMQ_50_60, {
        LLMQType::LLMQ_50_60,
        "llmq_50_60",
        50,     // size
        40,     // minSize
        60,     // threshold (percentage)
        24,     // dkgInterval (blocks)
        6,      // dkgPhaseBlocks
        24      // signingActiveQuorumCount
    }},
    {LLMQType::LLMQ_400_60, {
        LLMQType::LLMQ_400_60,
        "llmq_400_60",
        400,    // size
        300,    // minSize
        60,     // threshold
        288,    // dkgInterval (~12 hours at 1 min blocks)
        20,     // dkgPhaseBlocks
        4       // signingActiveQuorumCount
    }},
    {LLMQType::LLMQ_400_85, {
        LLMQType::LLMQ_400_85,
        "llmq_400_85",
        400,
        350,
        85,
        576,    // ~24 hours
        20,
        4
    }},
    {LLMQType::LLMQ_100_67, {
        LLMQType::LLMQ_100_67,
        "llmq_100_67",
        100,
        80,
        67,
        24,
        6,
        24
    }},
    {LLMQType::LLMQ_5_60, {
        LLMQType::LLMQ_5_60,
        "llmq_5_60",
        5,      // size
        3,      // minSize
        60,     // threshold (percentage)
        12,     // dkgInterval (blocks)
        2,      // dkgPhaseBlocks  
        4       // signingActiveQuorumCount
    }},
};

const LLMQParams& GetLLMQParams(LLMQType type)
{
    static const LLMQParams defaultParams = {LLMQType::LLMQ_NONE, "none", 0, 0, 0, 0, 0, 0};
    auto it = llmqParams.find(type);
    if (it == llmqParams.end()) {
        return defaultParams;
    }
    return it->second;
}

// ============================================================================
// CQuorum Implementation
// ============================================================================

int CQuorum::GetMemberIndex(const uint256& proTxHash) const
{
    for (size_t i = 0; i < members.size(); i++) {
        if (members[i].proTxHash == proTxHash) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

bool CQuorum::IsMember(const uint256& proTxHash) const
{
    if (!membersCached) {
        for (const auto& m : members) {
            memberProTxHashes.insert(m.proTxHash);
        }
        membersCached = true;
    }
    return memberProTxHashes.count(proTxHash) > 0;
}

std::vector<CBLSPublicKey> CQuorum::GetMemberPublicKeys() const
{
    std::vector<CBLSPublicKey> keys;
    keys.reserve(members.size());
    for (const auto& m : members) {
        if (m.valid) {
            keys.push_back(m.pubKeyOperator);
        }
    }
    return keys;
}

int CQuorum::GetThreshold() const
{
    const auto& params = GetLLMQParams(llmqType);
    return (validMemberCount * params.threshold + 99) / 100;
}

int CQuorum::GetMinSize() const
{
    return GetLLMQParams(llmqType).minSize;
}

std::string CQuorum::ToString() const
{
    std::ostringstream ss;
    ss << "CQuorum("
       << "type=" << static_cast<int>(llmqType)
       << ", hash=" << quorumHash.ToString().substr(0, 16)
       << ", height=" << quorumHeight
       << ", members=" << members.size()
       << ", valid=" << validMemberCount
       << ")";
    return ss.str();
}

// ============================================================================
// CRecoveredSig Implementation
// ============================================================================

uint256 CRecoveredSig::GetHash() const
{
    if (!hashCached.load(std::memory_order_acquire)) {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << *this;
        hash = hw.GetHash();
        hashCached.store(true, std::memory_order_release);
    }
    return hash;
}

uint256 CRecoveredSig::BuildSignHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    // Include genesis block hash for chain binding to prevent cross-chain replay attacks
    hw << Params().GenesisBlock().GetHash();
    hw << static_cast<uint8_t>(llmqType);
    hw << quorumHash;
    hw << id;
    hw << msgHash;
    return hw.GetHash();
}

std::string CRecoveredSig::ToString() const
{
    std::ostringstream ss;
    ss << "CRecoveredSig("
       << "type=" << static_cast<int>(llmqType)
       << ", quorum=" << quorumHash.ToString().substr(0, 16)
       << ", id=" << id.ToString().substr(0, 16)
       << ")";
    return ss.str();
}

// ============================================================================
// CQuorumManager Implementation
// ============================================================================

CQuorumManager::CQuorumManager()
{
}

void CQuorumManager::SetMyProTxHash(const uint256& _proTxHash)
{
    LOCK(cs);
    myProTxHash = _proTxHash;
}

CQuorumCPtr CQuorumManager::BuildQuorum(LLMQType type, const CBlockIndex* pindex)
{
    LOCK(cs);
    
    if (!pindex) {
        return nullptr;
    }
    
    const auto& params = GetLLMQParams(type);
    if (params.type == LLMQType::LLMQ_NONE) {
        return nullptr;
    }
    
    // Calculate quorum hash (deterministic from block hash and type)
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("LLMQ_QUORUM");
    hw << static_cast<uint8_t>(type);
    hw << pindex->GetBlockHash();
    uint256 quorumHash = hw.GetHash();
    
    // Check cache
    auto key = std::make_pair(type, quorumHash);
    auto it = quorumCache.find(key);
    if (it != quorumCache.end()) {
        return it->second;
    }
    
    // Select members
    auto selectedMembers = SelectQuorumMembers(type, pindex);
    if (selectedMembers.size() < static_cast<size_t>(params.minSize)) {
        LogPrintf("CQuorumManager::%s -- Not enough MNs for quorum type %d at height %d\n",
                  __func__, static_cast<int>(type), pindex->nHeight);
        return nullptr;
    }
    
    // Build quorum
    auto quorum = std::make_shared<CQuorum>();
    quorum->llmqType = type;
    quorum->quorumHash = quorumHash;
    quorum->quorumHeight = pindex->nHeight;
    
    // Add members
    quorum->members.reserve(selectedMembers.size());
    std::vector<CBLSPublicKey> memberPubKeys;
    
    for (const auto& mn : selectedMembers) {
        CQuorumMember member;
        member.proTxHash = mn->proTxHash;
        
        // Get BLS public key from operator key
        CBLSPublicKey opKey;
        if (!mn->state.vchOperatorPubKey.empty()) {
            opKey.SetBytes(mn->state.vchOperatorPubKey);
        }
        member.pubKeyOperator = opKey;
        member.valid = opKey.IsValid() && mn->IsValid();
        
        if (member.valid) {
            memberPubKeys.push_back(opKey);
            quorum->validMemberCount++;
        }
        
        quorum->members.push_back(member);
    }
    
    // Derive quorum public key.
    // After nConsensusFixHeight, prefer the DKG-derived threshold public key
    // from the final commitment (first element of the verification vector).
    // Before that, fall back to naive aggregation for backward compatibility.
    const auto& cp = GetParams().GetConsensus();
    bool usedDKGKey = false;
    if (pindex->nHeight >= cp.nConsensusFixHeight && dkgSessionManager) {
        CDKGFinalCommitment commitment;
        if (dkgSessionManager->GetFinalCommitment(quorumHash, commitment) &&
            commitment.quorumPublicKey.IsValid()) {
            quorum->quorumPublicKey = commitment.quorumPublicKey;
            usedDKGKey = true;
        }
    }
    if (!usedDKGKey && !memberPubKeys.empty()) {
        quorum->quorumPublicKey = CBLSPublicKey::AggregatePublicKeys(memberPubKeys);
    }
    
    quorum->fValid = (quorum->validMemberCount >= params.minSize);
    
    // Evict oldest cache entries to bound memory usage
    static const size_t MAX_QUORUM_CACHE = 256;
    while (quorumCache.size() >= MAX_QUORUM_CACHE) {
        quorumCache.erase(quorumCache.begin());
    }
    
    quorumCache[key] = quorum;
    
    LogPrintf("CQuorumManager::%s -- Built quorum: %s\n", __func__, quorum->ToString());
    
    // Log quorum health metrics including eclipse attack indicators
    LogQuorumHealth(quorum);
    
    return quorum;
}

CQuorumCPtr CQuorumManager::GetQuorum(LLMQType type, const uint256& quorumHash) const
{
    LOCK(cs);
    auto it = quorumCache.find(std::make_pair(type, quorumHash));
    if (it != quorumCache.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<CQuorumCPtr> CQuorumManager::GetActiveQuorums(LLMQType type) const
{
    LOCK(cs);
    auto it = activeQuorums.find(type);
    if (it != activeQuorums.end()) {
        return it->second;
    }
    return {};
}

CQuorumCPtr CQuorumManager::SelectQuorumForSigning(
    LLMQType type, 
    const CBlockIndex* pindex,
    const uint256& selectionHash) const
{
    LOCK(cs);
    
    auto quorums = GetActiveQuorums(type);
    if (quorums.empty()) {
        return nullptr;
    }
    
    // Select based on score
    CQuorumCPtr bestQuorum = nullptr;
    uint256 bestScore;
    
    for (const auto& quorum : quorums) {
        if (!quorum->IsValid()) continue;
        
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << std::string("LLMQ_SELECT");
        hw << quorum->quorumHash;
        hw << selectionHash;
        uint256 score = hw.GetHash();
        
        if (!bestQuorum || score < bestScore) {
            bestQuorum = quorum;
            bestScore = score;
        }
    }
    
    return bestQuorum;
}

void CQuorumManager::UpdatedBlockTip(const CBlockIndex* pindex)
{
    if (!pindex) return;
    
    // Try to initialize masternode identity if we have a pending key
    // This retries each block until successful (after sync is complete)
    TryInitMasternodeIdentity();
    
    LOCK(cs);
    
    // Update active quorums for each type
    for (const auto& [type, params] : llmqParams) {
        if (params.type == LLMQType::LLMQ_NONE) continue;
        
        // Calculate which heights should have quorums
        int quorumHeight = pindex->nHeight - (pindex->nHeight % params.dkgInterval);
        
        std::vector<CQuorumCPtr> newActive;
        
        // Build quorums for recent heights
        for (int i = 0; i < params.signingActiveQuorumCount && quorumHeight > 0; i++) {
            const CBlockIndex* quorumIndex = pindex->GetAncestor(quorumHeight);
            if (quorumIndex) {
                auto quorum = BuildQuorum(type, quorumIndex);
                if (quorum && quorum->IsValid()) {
                    newActive.push_back(quorum);
                }
            }
            quorumHeight -= params.dkgInterval;
        }
        
        activeQuorums[type] = newActive;
    }
}

bool CQuorumManager::IsQuorumMember(LLMQType type, const uint256& quorumHash) const
{
    LOCK(cs);
    
    if (myProTxHash.IsNull()) return false;
    
    auto quorum = GetQuorum(type, quorumHash);
    if (!quorum) return false;
    
    return quorum->IsMember(myProTxHash);
}

bool CQuorumManager::GetSecretKeyShare(
    LLMQType type, 
    const uint256& quorumHash,
    CBLSSecretKey& skShareOut) const
{
    LOCK(cs);
    
    auto quorum = GetQuorum(type, quorumHash);
    if (!quorum) {
        LogPrint(BCLog::LLMQ, "CQuorumManager::GetSecretKeyShare -- quorum not found: %s\n",
                 quorumHash.ToString().substr(0, 16));
        return false;
    }
    
    // =====================================================================
    // SECURITY: Only use DKG-generated secret key shares
    //
    // Secret key shares MUST come from the DKG protocol. Using any other
    // source (deterministic derivation, stored keys, etc.) completely
    // breaks threshold security as it allows any party to derive shares.
    //
    // The DKG protocol ensures:
    // 1. No single party knows the combined secret key
    // 2. Threshold parties are required to sign
    // 3. Shares are distributed with verifiable commitments
    //
    // DO NOT add fallbacks that bypass DKG, even for testing.
    // For tests, run actual DKG or mock the entire signing flow.
    // =====================================================================
    
    if (dkgSessionManager) {
        if (dkgSessionManager->GetSecretKeyShare(quorumHash, skShareOut)) {
            LogPrint(BCLog::LLMQ, "CQuorumManager::GetSecretKeyShare -- got DKG share for quorum %s\n",
                     quorumHash.ToString().substr(0, 16));
            return true;
        }
    }
    
    // =====================================================================
    // SECURITY: No fallback - DKG is the only valid source
    //
    // If DKG share is not available, it means:
    // 1. We were not a quorum member, OR
    // 2. DKG did not complete successfully, OR
    // 3. The share was not persisted correctly
    //
    // In all cases, attempting to participate in signing would be
    // insecure and should not be allowed.
    // =====================================================================
    
    LogPrintf("CQuorumManager::GetSecretKeyShare -- no DKG share available for quorum %s\n",
              quorumHash.ToString().substr(0, 16));
    LogPrintf("CQuorumManager::GetSecretKeyShare -- this node cannot participate in signing for this quorum\n");
    
    return false;
}

std::vector<CDeterministicMNCPtr> CQuorumManager::SelectQuorumMembers(
    LLMQType type,
    const CBlockIndex* pindex) const
{
    const auto& params = GetLLMQParams(type);
    
    // Get the masternode list at this height
    auto mnList = deterministicMNManager->GetListForBlock(pindex);
    if (!mnList) {
        return {};
    }
    
    // Calculate quorum modifier
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("LLMQ_MODIFIER");
    hw << static_cast<uint8_t>(type);
    hw << pindex->GetBlockHash();
    uint256 quorumModifier = hw.GetHash();
    
    // Score all valid masternodes
    std::vector<std::pair<uint256, CDeterministicMNCPtr>> scored;
    
    mnList->ForEachMN(true, [&](const CDeterministicMNCPtr& mn) {
        if (mn->state.vchOperatorPubKey.empty()) return;
        
        uint256 score = CalcMemberScore(mn, quorumModifier);
        scored.emplace_back(score, mn);
    });
    
    // Sort by score
    std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
    });
    
    // Take top N
    std::vector<CDeterministicMNCPtr> result;
    result.reserve(std::min(scored.size(), static_cast<size_t>(params.size)));
    
    for (size_t i = 0; i < scored.size() && result.size() < static_cast<size_t>(params.size); i++) {
        result.push_back(scored[i].second);
    }
    
    return result;
}

uint256 CQuorumManager::CalcMemberScore(
    const CDeterministicMNCPtr& mn,
    const uint256& quorumModifier) const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("LLMQ_SCORE");
    hw << quorumModifier;
    hw << mn->proTxHash;
    return hw.GetHash();
}

// ============================================================================
// Eclipse Attack Protection
// ============================================================================

uint32_t CQuorumManager::GetSubnet16(const CService& addr) const
{
    // Extract the /16 subnet (first two octets for IPv4)
    // For IPv6, we use a similar concept with the first 32 bits
    if (addr.IsIPv4()) {
        // Extract first two bytes of IPv4 address
        std::vector<unsigned char> ipBytes(16);
        addr.GetIn6Addr(reinterpret_cast<struct in6_addr*>(ipBytes.data()));
        // IPv4-mapped IPv6 addresses have IPv4 in last 4 bytes
        return (static_cast<uint32_t>(ipBytes[12]) << 8) | ipBytes[13];
    } else {
        // For IPv6, use first 32 bits
        std::vector<unsigned char> ipBytes(16);
        addr.GetIn6Addr(reinterpret_cast<struct in6_addr*>(ipBytes.data()));
        return (static_cast<uint32_t>(ipBytes[0]) << 24) |
               (static_cast<uint32_t>(ipBytes[1]) << 16) |
               (static_cast<uint32_t>(ipBytes[2]) << 8) |
               ipBytes[3];
    }
}

size_t CQuorumManager::GetQuorumSubnetDiversity(const CQuorumCPtr& quorum) const
{
    if (!quorum || quorum->members.empty()) {
        return 0;
    }
    
    std::set<uint32_t> subnets;
    
    for (const auto& member : quorum->members) {
        if (!member.valid) continue;
        
        // Get the masternode's service address
        auto mn = deterministicMNManager->GetMN(member.proTxHash);
        if (mn) {
            uint32_t subnet = GetSubnet16(mn->state.addr);
            subnets.insert(subnet);
        }
    }
    
    return subnets.size();
}

bool CQuorumManager::CheckQuorumDistribution(const CQuorumCPtr& quorum) const
{
    if (!quorum || !quorum->IsValid()) {
        return false;
    }
    
    // Calculate subnet diversity
    size_t uniqueSubnets = GetQuorumSubnetDiversity(quorum);
    size_t memberCount = quorum->validMemberCount;
    
    // ============================================================
    // Eclipse Attack Detection Heuristics
    //
    // Warning thresholds:
    // - Less than 50% subnet diversity is concerning
    // - Less than 25% subnet diversity is critical
    //
    // A healthy quorum should have members distributed across
    // many different network subnets to resist eclipse attacks
    // where an attacker controls a subnet.
    // ============================================================
    
    if (memberCount == 0) {
        return false;
    }
    
    double diversityRatio = static_cast<double>(uniqueSubnets) / memberCount;
    
    if (diversityRatio < 0.25) {
        LogPrintf("SECURITY WARNING: Quorum %s has CRITICAL low subnet diversity: %zu subnets for %zu members (%.1f%%)\n",
                  quorum->quorumHash.ToString().substr(0, 16),
                  uniqueSubnets, memberCount, diversityRatio * 100);
        LogPrintf("This may indicate an eclipse attack or network centralization risk.\n");
        return false;
    }
    
    if (diversityRatio < 0.50) {
        LogPrintf("SECURITY NOTICE: Quorum %s has low subnet diversity: %zu subnets for %zu members (%.1f%%)\n",
                  quorum->quorumHash.ToString().substr(0, 16),
                  uniqueSubnets, memberCount, diversityRatio * 100);
    }
    
    return true;
}

void CQuorumManager::LogQuorumHealth(const CQuorumCPtr& quorum) const
{
    if (!quorum) {
        return;
    }
    
    size_t uniqueSubnets = GetQuorumSubnetDiversity(quorum);
    size_t memberCount = quorum->validMemberCount;
    size_t threshold = quorum->GetThreshold();
    
    LogPrint(BCLog::LLMQ, "Quorum Health: %s - members=%zu, valid=%zu, threshold=%zu, subnets=%zu\n",
             quorum->quorumHash.ToString().substr(0, 16),
             quorum->members.size(), memberCount, threshold, uniqueSubnets);
    
    // Check distribution and log any warnings
    CheckQuorumDistribution(quorum);
    
    // Record in monitoring system for alerting and metrics
    if (quorumMonitor) {
        quorumMonitor->RecordQuorumHealth(quorum);
    }
}

// ============================================================================
// CSigningManager Implementation
// ============================================================================

CSigningManager::CSigningManager(CQuorumManager& _quorumManager)
    : quorumManager(_quorumManager)
{
}

bool CSigningManager::AsyncSign(LLMQType type, const uint256& id, const uint256& msgHash)
{
    LOCK(cs);
    
    LOCK(cs_main);
    auto quorum = quorumManager.SelectQuorumForSigning(type, chainActive.Tip(), id);
    if (!quorum) {
        LogPrintf("CSigningManager::%s -- No quorum available for signing\n", __func__);
        return false;
    }
    
    CBLSSecretKey skShare;
    if (!quorumManager.GetSecretKeyShare(type, quorum->quorumHash, skShare)) {
        LogPrintf("CSigningManager::%s -- Not a quorum member\n", __func__);
        return false;
    }
    
    // Build sign hash
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << static_cast<uint8_t>(type);
    hw << quorum->quorumHash;
    hw << id;
    hw << msgHash;
    uint256 signHash = hw.GetHash();
    
    // Sign with domain separation to prevent cross-context signature reuse
    CBLSSignature sigShare = skShare.SignWithDomain(signHash, BLSDomainTags::QUORUM);
    if (!sigShare.IsValid()) {
        LogPrintf("CSigningManager::%s -- Failed to create signature share\n", __func__);
        return false;
    }
    
    // Store our share
    sigShares[id][quorumManager.GetMyProTxHash()] = sigShare;
    
    LogPrintf("CSigningManager::%s -- Created sig share for %s\n", 
              __func__, id.ToString().substr(0, 16));
    
    // Try to recover
    CRecoveredSig recSig;
    if (TryRecoverSignature(type, id, msgHash, recSig)) {
        recoveredSigs[id] = recSig;
        LogPrintf("CSigningManager::%s -- Recovered signature for %s\n",
                  __func__, id.ToString().substr(0, 16));
    }
    
    return true;
}

bool CSigningManager::ProcessSigShare(
    LLMQType type,
    const uint256& quorumHash,
    const uint256& id,
    const uint256& proTxHash,
    const CBLSSignature& sigShare)
{
    LOCK(cs);
    
    if (!sigShare.IsValid()) {
        return false;
    }
    
    // Check for equivocation before storing
    if (equivocationManager) {
        // Build context hash from id (signing request identifier)
        CHashWriter hw(SER_GETHASH, 0);
        hw << std::string("LLMQ_SIG_CONTEXT");
        hw << quorumHash;
        hw << id;
        uint256 contextHash = hw.GetHash();
        
        // Build message hash (what was signed)
        CHashWriter mhw(SER_GETHASH, 0);
        mhw << id;
        uint256 msgHash = mhw.GetHash();
        
        // Get member's public key for verification
        LOCK(cs_main);
        auto quorum = quorumManager.GetQuorum(type, quorumHash);
        if (quorum) {
            int memberIdx = quorum->GetMemberIndex(proTxHash);
            if (memberIdx >= 0 && memberIdx < static_cast<int>(quorum->members.size())) {
                const CBLSPublicKey& memberPk = quorum->members[memberIdx].pubKeyOperator;
                
                // Record the signature for equivocation detection
                if (!equivocationManager->RecordSignature(contextHash, quorumHash, proTxHash, 
                                                          msgHash, sigShare, memberPk)) {
                    LogPrintf("CSigningManager::ProcessSigShare -- EQUIVOCATION from %s\n",
                              proTxHash.ToString().substr(0, 16));
                    return false;
                }
            }
        }
    }
    
    // Store the share
    sigShares[id][proTxHash] = sigShare;
    
    return true;
}

bool CSigningManager::TryRecoverSignature(
    LLMQType type,
    const uint256& id,
    const uint256& msgHash,
    CRecoveredSig& recSigOut)
{
    LOCK(cs);
    
    // Already recovered?
    auto it = recoveredSigs.find(id);
    if (it != recoveredSigs.end()) {
        recSigOut = it->second;
        return true;
    }
    
    // Get shares for this id
    auto sharesIt = sigShares.find(id);
    if (sharesIt == sigShares.end()) {
        return false;
    }
    
    const auto& shares = sharesIt->second;
    
    LOCK(cs_main);
    auto quorum = quorumManager.SelectQuorumForSigning(type, chainActive.Tip(), id);
    if (!quorum) {
        return false;
    }
    
    // Check if we have enough shares
    int threshold = quorum->GetThreshold();
    if (static_cast<int>(shares.size()) < threshold) {
        return false;
    }
    
    // Collect shares from members
    // ============================================================
    // SECURITY FIX: Use actual member indices for Lagrange interpolation
    //
    // In DKG, polynomial shares are evaluated at points x = memberIndex + 1
    // (1-indexed: member 0 evaluates at x=1, member 1 at x=2, etc.)
    //
    // For threshold recovery, we MUST use these same indices. Using
    // arbitrary IDs (like proTxHash) or sequential indices (1,2,3...)
    // when shares come from non-sequential members produces WRONG results.
    //
    // Example: If we receive shares from members 3, 7, 12, we must use
    // evaluation points 4, 8, 13 (not 1, 2, 3) for correct interpolation.
    // ============================================================
    std::vector<CBLSSignature> memberSigs;
    std::vector<uint64_t> memberIndices;
    
    for (const auto& [proTxHash, sig] : shares) {
        int memberIdx = quorum->GetMemberIndex(proTxHash);
        if (memberIdx >= 0) {
            memberSigs.push_back(sig);
            // Use 1-indexed member position to match DKG polynomial evaluation point
            memberIndices.push_back(static_cast<uint64_t>(memberIdx + 1));
            
            if (static_cast<int>(memberSigs.size()) >= threshold) {
                break;
            }
        }
    }
    
    if (static_cast<int>(memberSigs.size()) < threshold) {
        return false;
    }
    
    // Recover threshold signature using actual member indices
    CBLSSignature recoveredSig = CBLSSignature::RecoverThresholdSignatureWithIndices(
        memberSigs, memberIndices, threshold);
    
    if (!recoveredSig.IsValid()) {
        return false;
    }
    
    // Build result
    recSigOut.llmqType = type;
    recSigOut.quorumHash = quorum->quorumHash;
    recSigOut.id = id;
    recSigOut.msgHash = msgHash;
    recSigOut.sig = recoveredSig;
    
    return true;
}

bool CSigningManager::GetRecoveredSig(const uint256& id, CRecoveredSig& recSigOut) const
{
    LOCK(cs);
    
    auto it = recoveredSigs.find(id);
    if (it == recoveredSigs.end()) {
        return false;
    }
    
    recSigOut = it->second;
    return true;
}

bool CSigningManager::VerifyRecoveredSig(const CRecoveredSig& recSig) const
{
    if (!recSig.sig.IsValid()) {
        return false;
    }
    
    auto quorum = quorumManager.GetQuorum(recSig.llmqType, recSig.quorumHash);
    if (!quorum || !quorum->IsValid()) {
        return false;
    }
    
    // Verify against quorum public key with domain separation
    uint256 signHash = recSig.BuildSignHash();
    return recSig.sig.VerifyWithDomain(quorum->quorumPublicKey, signHash, BLSDomainTags::QUORUM);
}

void CSigningManager::Cleanup(int currentHeight)
{
    LOCK(cs);
    
    // ============================================================
    // SECURITY FIX: Use height-based LRU eviction instead of clear-all
    //
    // The previous implementation cleared ALL entries when cache
    // exceeded 10000, which could break in-progress signing sessions
    // and cause threshold recovery to fail.
    //
    // New approach: Remove entries older than a threshold height,
    // keeping recent entries that may still be needed for recovery.
    // ============================================================
    
    // Height window for keeping shares (e.g., 100 blocks ~ 100 minutes)
    static const int SHARE_EXPIRY_BLOCKS = 100;
    
    // Maximum entries before forced cleanup
    static const size_t MAX_SHARES = 10000;
    static const size_t MAX_RECOVERED = 10000;
    
    // Clean up old signature shares by removing entries for old signing requests
    // We keep shares for recent heights to allow threshold recovery to complete
    if (sigShares.size() > MAX_SHARES / 2) {
        size_t removed = 0;
        size_t targetRemove = sigShares.size() - MAX_SHARES / 2;
        
        // Remove oldest entries first (by iteration order, which is insertion order for map)
        for (auto it = sigShares.begin(); it != sigShares.end() && removed < targetRemove; ) {
            // If we have a lot of entries, be more aggressive
            if (sigShares.size() > MAX_SHARES) {
                it = sigShares.erase(it);
                removed++;
            } else {
                // Keep if we're within limits
                break;
            }
        }
        
        if (removed > 0) {
            LogPrint(BCLog::LLMQ, "CSigningManager::%s -- Evicted %zu old signature share entries (remaining: %zu)\n",
                     __func__, removed, sigShares.size());
        }
    }
    
    // Clean up recovered signatures - these are safe to remove once propagated
    if (recoveredSigs.size() > MAX_RECOVERED / 2) {
        size_t removed = 0;
        size_t targetRemove = recoveredSigs.size() - MAX_RECOVERED / 2;
        
        for (auto it = recoveredSigs.begin(); it != recoveredSigs.end() && removed < targetRemove; ) {
            if (recoveredSigs.size() > MAX_RECOVERED) {
                it = recoveredSigs.erase(it);
                removed++;
            } else {
                break;
            }
        }
        
        if (removed > 0) {
            LogPrint(BCLog::LLMQ, "CSigningManager::%s -- Evicted %zu old recovered signature entries (remaining: %zu)\n",
                     __func__, removed, recoveredSigs.size());
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

// Pending masternode operator key (stored for retry after sync)
static std::string pendingOperatorKeyHex;
static bool masternodeIdentityInitialized = false;

void InitLLMQ()
{
    BLSInit();
    
    quorumManager = std::make_unique<CQuorumManager>();
    signingManager = std::make_unique<CSigningManager>(*quorumManager);
    
    // Initialize DKG subsystem for secure quorum key generation
    InitDKG(*quorumManager);
    
    // Initialize equivocation detection
    InitEquivocationDetection();
    
    // Initialize monitoring system for quorum health and security alerts
    InitQuorumMonitoring();
    
    // Create and register validation interface for block notifications
    llmqValidationInterface = std::make_unique<CLLMQValidationInterface>();
    RegisterValidationInterface(llmqValidationInterface.get());
    
    LogPrintf("LLMQ subsystem initialized (with DKG, equivocation detection, and monitoring)\n");
}

void SetPendingMasternodeKey(const std::string& operatorKeyHex)
{
    pendingOperatorKeyHex = operatorKeyHex;
    masternodeIdentityInitialized = false;
}

bool TryInitMasternodeIdentity()
{
    if (masternodeIdentityInitialized || pendingOperatorKeyHex.empty()) {
        return masternodeIdentityInitialized;
    }
    
    if (InitMasternodeIdentity(pendingOperatorKeyHex)) {
        masternodeIdentityInitialized = true;
        // Clear the key from memory after successful initialization
        pendingOperatorKeyHex.clear();
        return true;
    }
    
    return false;
}

bool InitMasternodeIdentity(const std::string& operatorKeyHex)
{
    // Validate and parse the operator secret key
    if (operatorKeyHex.empty()) {
        return false;  // Not a masternode
    }
    
    std::vector<uint8_t> keyBytes = ParseHex(operatorKeyHex);
    if (keyBytes.size() != 32) {
        LogPrintf("InitMasternodeIdentity -- invalid operator key length: %zu (expected 32)\n", 
                  keyBytes.size());
        return false;
    }
    
    CBLSSecretKey operatorKey;
    if (!operatorKey.SetSecretKey(keyBytes)) {
        LogPrintf("InitMasternodeIdentity -- invalid operator secret key\n");
        return false;
    }
    
    // Derive the public key
    CBLSPublicKey operatorPubKey = operatorKey.GetPublicKey();
    if (!operatorPubKey.IsValid()) {
        LogPrintf("InitMasternodeIdentity -- failed to derive public key\n");
        return false;
    }
    
    // Find our proTxHash by matching operator public key
    if (!deterministicMNManager) {
        LogPrintf("InitMasternodeIdentity -- deterministic MN manager not initialized\n");
        return false;
    }
    
    auto mnList = deterministicMNManager->GetListAtChainTip();
    uint256 myProTxHash;
    bool found = false;
    
    mnList->ForEachMN(true, [&](const CDeterministicMNCPtr& mn) {
        if (!found && mn->state.vchOperatorPubKey.size() == 48) {
            CBLSPublicKey mnPubKey;
            if (mnPubKey.SetBytes(mn->state.vchOperatorPubKey)) {
                if (mnPubKey == operatorPubKey) {
                    myProTxHash = mn->proTxHash;
                    found = true;
                }
            }
        }
    });
    
    if (!found) {
        LogPrintf("InitMasternodeIdentity -- no registered masternode found with this operator key\n");
        return false;
    }
    
    // Configure DKG session manager with our identity
    if (dkgSessionManager) {
        dkgSessionManager->SetMyProTxHash(myProTxHash);
        if (!dkgSessionManager->SetMyOperatorKey(operatorKey)) {
            LogPrintf("InitMasternodeIdentity -- failed to set operator key in DKG manager\n");
            return false;
        }
    }
    
    LogPrintf("InitMasternodeIdentity -- configured as masternode %s\n", 
              myProTxHash.ToString().substr(0, 16));
    return true;
}

void StopLLMQ()
{
    // Unregister validation interface first
    if (llmqValidationInterface) {
        UnregisterValidationInterface(llmqValidationInterface.get());
        llmqValidationInterface.reset();
    }
    
    // Stop monitoring (prints summary report)
    StopQuorumMonitoring();
    
    // Stop equivocation detection
    StopEquivocationDetection();
    
    // Stop DKG
    StopDKG();
    
    signingManager.reset();
    quorumManager.reset();
    
    BLSCleanup();
    
    LogPrintf("LLMQ subsystem stopped\n");
}

} // namespace llmq

