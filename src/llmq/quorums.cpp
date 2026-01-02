// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/quorums.h"
#include "chain.h"
#include "chainparams.h"
#include "evo/deterministicmns.h"
#include "hash.h"
#include "util.h"
#include "validation.h"

#include <algorithm>
#include <sstream>

namespace llmq {

// Global instances
std::unique_ptr<CQuorumManager> quorumManager;
std::unique_ptr<CSigningManager> signingManager;

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
    if (!hashCached) {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << *this;
        hash = hw.GetHash();
        hashCached = true;
    }
    return hash;
}

uint256 CRecoveredSig::BuildSignHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << llmqType;
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
    hw << type;
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
    
    // Aggregate public key
    if (!memberPubKeys.empty()) {
        quorum->quorumPublicKey = CBLSPublicKey::AggregatePublicKeys(memberPubKeys);
    }
    
    quorum->fValid = (quorum->validMemberCount >= params.minSize);
    
    // Cache
    quorumCache[key] = quorum;
    
    LogPrintf("CQuorumManager::%s -- Built quorum: %s\n", __func__, quorum->ToString());
    
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
    LOCK(cs);
    
    if (!pindex) return;
    
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
    if (!quorum || !quorum->skShare) {
        return false;
    }
    
    // In production, this would return the DKG-generated share
    // For now, derive deterministically
    skShareOut.SetSecretKeyFromSeed(quorumHash);
    return true;
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
    hw << type;
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
    hw << type;
    hw << quorum->quorumHash;
    hw << id;
    hw << msgHash;
    uint256 signHash = hw.GetHash();
    
    // Sign
    CBLSSignature sigShare = skShare.Sign(signHash);
    if (!sigShare.IsValid()) {
        LogPrintf("CSigningManager::%s -- Failed to create signature share\n", __func__);
        return false;
    }
    
    // Store our share
    sigShares[id][quorumManager.myProTxHash] = sigShare;
    
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
    const uint256& quorumHash,
    const uint256& id,
    const uint256& proTxHash,
    const CBLSSignature& sigShare)
{
    LOCK(cs);
    
    if (!sigShare.IsValid()) {
        return false;
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
    std::vector<CBLSSignature> memberSigs;
    std::vector<CBLSId> memberIds;
    
    for (const auto& [proTxHash, sig] : shares) {
        if (quorum->IsMember(proTxHash)) {
            memberSigs.push_back(sig);
            memberIds.emplace_back(proTxHash);
            
            if (static_cast<int>(memberSigs.size()) >= threshold) {
                break;
            }
        }
    }
    
    if (static_cast<int>(memberSigs.size()) < threshold) {
        return false;
    }
    
    // Recover threshold signature
    CBLSSignature recoveredSig = CBLSSignature::RecoverThresholdSignature(
        memberSigs, memberIds, threshold);
    
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
    
    // Verify against quorum public key
    uint256 signHash = recSig.BuildSignHash();
    return recSig.sig.VerifyInsecure(quorum->quorumPublicKey, signHash);
}

void CSigningManager::Cleanup(int currentHeight)
{
    LOCK(cs);
    
    // Remove old signature sessions
    // In production, use proper expiry logic
    if (sigShares.size() > 10000) {
        sigShares.clear();
        LogPrintf("CSigningManager::%s -- Cleared signature shares cache\n", __func__);
    }
    
    if (recoveredSigs.size() > 10000) {
        recoveredSigs.clear();
        LogPrintf("CSigningManager::%s -- Cleared recovered sigs cache\n", __func__);
    }
}

// ============================================================================
// Initialization
// ============================================================================

void InitLLMQ()
{
    BLSInit();
    
    quorumManager = std::make_unique<CQuorumManager>();
    signingManager = std::make_unique<CSigningManager>(*quorumManager);
    
    LogPrintf("LLMQ subsystem initialized\n");
}

void StopLLMQ()
{
    signingManager.reset();
    quorumManager.reset();
    
    BLSCleanup();
    
    LogPrintf("LLMQ subsystem stopped\n");
}

} // namespace llmq

