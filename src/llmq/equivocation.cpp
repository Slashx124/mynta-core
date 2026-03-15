// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/equivocation.h"
#include "llmq/monitoring.h"
#include "bls/bls.h"
#include "evo/pose.h"
#include "chainparams.h"
#include "hash.h"
#include "util.h"
#include "validation.h"

#include <sstream>

namespace llmq {

// Global instance
std::unique_ptr<CEquivocationManager> equivocationManager;

// ============================================================================
// CEquivocationProof Implementation
// ============================================================================

uint256 CEquivocationProof::GetHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << *this;
    return hw.GetHash();
}

bool CEquivocationProof::Verify() const
{
    // Basic validation
    if (contextHash.IsNull() || proTxHash.IsNull()) {
        return false;
    }
    
    if (msgHash1.IsNull() || msgHash2.IsNull()) {
        return false;
    }
    
    // Messages must be different (that's what makes it equivocation)
    if (msgHash1 == msgHash2) {
        LogPrintf("CEquivocationProof::Verify -- messages are the same, not equivocation\n");
        return false;
    }
    
    // Both signatures must be valid
    if (!sig1.IsValid() || !sig2.IsValid()) {
        LogPrintf("CEquivocationProof::Verify -- invalid signature format\n");
        return false;
    }
    
    // Public key must be valid
    if (!memberPubKey.IsValid()) {
        LogPrintf("CEquivocationProof::Verify -- invalid member public key\n");
        return false;
    }
    
    // After nConsensusFixHeight use domain-separated verification (matches
    // SignWithDomain used in quorum signing).  Before the gate, fall back to
    // VerifyInsecure so proofs created by earlier code still validate.
    bool fUseDomain = false;
    {
        LOCK(cs_main);
        fUseDomain = (chainActive.Height() >= GetParams().GetConsensus().nConsensusFixHeight);
    }

    if (fUseDomain) {
        if (!sig1.VerifyWithDomain(memberPubKey, msgHash1, BLSDomainTags::QUORUM)) {
            LogPrintf("CEquivocationProof::Verify -- signature 1 verification failed\n");
            return false;
        }
        if (!sig2.VerifyWithDomain(memberPubKey, msgHash2, BLSDomainTags::QUORUM)) {
            LogPrintf("CEquivocationProof::Verify -- signature 2 verification failed\n");
            return false;
        }
    } else {
        if (!sig1.VerifyInsecure(memberPubKey, msgHash1)) {
            LogPrintf("CEquivocationProof::Verify -- signature 1 verification failed\n");
            return false;
        }
        if (!sig2.VerifyInsecure(memberPubKey, msgHash2)) {
            LogPrintf("CEquivocationProof::Verify -- signature 2 verification failed\n");
            return false;
        }
    }
    
    return true;
}

std::string CEquivocationProof::ToString() const
{
    std::ostringstream ss;
    ss << "CEquivocationProof("
       << "context=" << contextHash.ToString().substr(0, 16)
       << ", member=" << proTxHash.ToString().substr(0, 16)
       << ", msg1=" << msgHash1.ToString().substr(0, 16)
       << ", msg2=" << msgHash2.ToString().substr(0, 16)
       << ", quorum=" << quorumHash.ToString().substr(0, 16)
       << ", time=" << detectionTime
       << ")";
    return ss.str();
}

// ============================================================================
// CEquivocationManager Implementation
// ============================================================================

bool CEquivocationManager::RecordSignature(const uint256& contextHash,
                                            const uint256& quorumHash,
                                            const uint256& proTxHash,
                                            const uint256& msgHash,
                                            const CBLSSignature& sig,
                                            const CBLSPublicKey& memberPubKey)
{
    LOCK(cs);
    
    auto key = std::make_pair(contextHash, proTxHash);
    
    // Check if we already have a record for this context + member
    auto it = sigRecords.find(key);
    if (it != sigRecords.end()) {
        // Check if it's the same message (duplicate, not equivocation)
        if (it->second.msgHash == msgHash) {
            // Same message, same signature - just a duplicate
            return true;
        }
        
        // Different message for same context! This is equivocation!
        LogPrintf("CEquivocationManager::RecordSignature -- EQUIVOCATION DETECTED! "
                  "Member %s signed different messages for context %s\n",
                  proTxHash.ToString().substr(0, 16), contextHash.ToString().substr(0, 16));
        
        // Create the conflicting record
        CSignatureRecord conflicting;
        conflicting.quorumHash = quorumHash;
        conflicting.proTxHash = proTxHash;
        conflicting.msgHash = msgHash;
        conflicting.sig = sig;
        conflicting.timestamp = GetTime();
        
        // Create and store the equivocation proof
        CreateEquivocationProof(contextHash, it->second, conflicting, memberPubKey);
        
        return false;  // Indicate equivocation was detected
    }
    
    // No existing record - store this one
    CSignatureRecord record;
    record.quorumHash = quorumHash;
    record.proTxHash = proTxHash;
    record.msgHash = msgHash;
    record.sig = sig;
    record.timestamp = GetTime();
    
    sigRecords[key] = record;
    
    return true;
}

void CEquivocationManager::CreateEquivocationProof(const uint256& contextHash,
                                                    const CSignatureRecord& existing,
                                                    const CSignatureRecord& conflicting,
                                                    const CBLSPublicKey& memberPubKey)
{
    // Called with lock held
    
    CEquivocationProof proof;
    proof.contextHash = contextHash;
    proof.proTxHash = existing.proTxHash;
    proof.msgHash1 = existing.msgHash;
    proof.sig1 = existing.sig;
    proof.msgHash2 = conflicting.msgHash;
    proof.sig2 = conflicting.sig;
    proof.quorumHash = existing.quorumHash;
    proof.memberPubKey = memberPubKey;
    proof.detectionTime = GetTime();
    
    // Verify the proof is valid before storing
    if (!proof.Verify()) {
        LogPrintf("CEquivocationManager::CreateEquivocationProof -- proof failed verification\n");
        return;
    }
    
    uint256 proofHash = proof.GetHash();
    
    // Store the proof
    equivocationProofs[proofHash] = proof;
    equivocators.insert(proof.proTxHash);
    
    LogPrintf("CEquivocationManager::CreateEquivocationProof -- %s\n", proof.ToString());
    
    // Record in monitoring system for alerting
    if (quorumMonitor) {
        quorumMonitor->RecordEquivocation(proof);
    }
    
    // Notify callbacks
    NotifyEquivocation(proof);
}

bool CEquivocationManager::HasEquivocated(const uint256& proTxHash) const
{
    LOCK(cs);
    return equivocators.count(proTxHash) > 0;
}

std::vector<CEquivocationProof> CEquivocationManager::GetEquivocationProofs(const uint256& proTxHash) const
{
    LOCK(cs);
    
    std::vector<CEquivocationProof> result;
    for (const auto& [hash, proof] : equivocationProofs) {
        if (proof.proTxHash == proTxHash) {
            result.push_back(proof);
        }
    }
    return result;
}

std::set<uint256> CEquivocationManager::GetAllEquivocators() const
{
    LOCK(cs);
    return equivocators;
}

bool CEquivocationManager::ProcessEquivocationProof(const CEquivocationProof& proof, CValidationState& state)
{
    LOCK(cs);
    
    // Verify the proof
    if (!proof.Verify()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-equivocation-proof",
                        false, "Equivocation proof verification failed");
    }
    
    // Check if we already have this proof
    uint256 proofHash = proof.GetHash();
    if (equivocationProofs.count(proofHash)) {
        // Already known, not an error
        return true;
    }
    
    // Store the proof
    equivocationProofs[proofHash] = proof;
    equivocators.insert(proof.proTxHash);
    
    LogPrintf("CEquivocationManager::ProcessEquivocationProof -- accepted proof: %s\n", proof.ToString());
    
    // Notify callbacks
    NotifyEquivocation(proof);
    
    return true;
}

void CEquivocationManager::RegisterCallback(EquivocationCallback callback)
{
    LOCK(cs);
    callbacks.push_back(std::move(callback));
}

void CEquivocationManager::NotifyEquivocation(const CEquivocationProof& proof)
{
    // Called with lock held - copy callbacks to avoid deadlock
    std::vector<EquivocationCallback> callbacksCopy;
    {
        // Already locked
        callbacksCopy = callbacks;
    }
    
    // Release lock before calling callbacks
    // Note: This is safe because callbacks is copied
    for (const auto& callback : callbacksCopy) {
        try {
            callback(proof);
        } catch (const std::exception& e) {
            LogPrintf("CEquivocationManager: callback exception: %s\n", e.what());
        }
    }
}

void CEquivocationManager::Cleanup(int currentHeight)
{
    LOCK(cs);
    
    if (currentHeight - lastCleanupHeight < CLEANUP_INTERVAL) {
        return;
    }
    
    lastCleanupHeight = currentHeight;
    
    // Remove old signature records if we have too many
    if (sigRecords.size() > MAX_RECORDS) {
        // Find and remove oldest records
        int64_t cutoffTime = GetTime() - 24 * 60 * 60;  // 24 hours ago
        
        auto it = sigRecords.begin();
        while (it != sigRecords.end() && sigRecords.size() > MAX_RECORDS / 2) {
            if (it->second.timestamp < cutoffTime) {
                it = sigRecords.erase(it);
            } else {
                ++it;
            }
        }
        
        LogPrint(BCLog::LLMQ, "CEquivocationManager: cleaned up, %zu records remaining\n", sigRecords.size());
    }
}

size_t CEquivocationManager::GetRecordCount() const
{
    LOCK(cs);
    return sigRecords.size();
}

size_t CEquivocationManager::GetEquivocatorCount() const
{
    LOCK(cs);
    return equivocators.size();
}

// ============================================================================
// Global Initialization
// ============================================================================

void InitEquivocationDetection()
{
    equivocationManager = std::make_unique<CEquivocationManager>();
    
    // Connect to PoSe system
    ConnectEquivocationToPoSe();
    
    LogPrintf("Equivocation detection initialized\n");
}

void StopEquivocationDetection()
{
    equivocationManager.reset();
    LogPrintf("Equivocation detection stopped\n");
}

void ConnectEquivocationToPoSe()
{
    if (!equivocationManager) return;
    
    // Register callback to penalize equivocators via PoSe
    equivocationManager->RegisterCallback([](const CEquivocationProof& proof) {
        if (!poseManager) return;
        
        // Apply severe penalty for equivocation (immediate ban)
        const auto& consensusParams = GetParams().GetConsensus();
        int banPenalty = consensusParams.nPoSeBanThreshold;
        
        LogPrintf("ConnectEquivocationToPoSe: Applying ban penalty to equivocator %s\n",
                  proof.proTxHash.ToString().substr(0, 16));
        
        poseManager->IncrementPenalty(proof.proTxHash, banPenalty);
        
        // Record the PoSe ban in monitoring system
        if (quorumMonitor) {
            quorumMonitor->RecordPoSeBan(proof.proTxHash);
        }
    });
}

} // namespace llmq
