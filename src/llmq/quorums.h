// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MYNTA_LLMQ_QUORUMS_H
#define MYNTA_LLMQ_QUORUMS_H

#include "bls/bls.h"
#include "evo/deterministicmns.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"

#include <map>
#include <memory>
#include <set>
#include <vector>

class CBlockIndex;
class CValidationState;

namespace llmq {

/**
 * Quorum Type - Different quorums for different purposes
 */
enum class LLMQType : uint8_t {
    LLMQ_NONE = 0,
    LLMQ_50_60 = 1,    // 50 members, 60% threshold (InstantSend)
    LLMQ_400_60 = 2,   // 400 members, 60% threshold (ChainLocks)
    LLMQ_400_85 = 3,   // 400 members, 85% threshold (Platform)
    LLMQ_100_67 = 4,   // 100 members, 67% threshold (General purpose)
};

// Quorum parameters
struct LLMQParams {
    LLMQType type;
    std::string name;
    int size;           // Number of members
    int minSize;        // Minimum members for valid quorum
    int threshold;      // Signing threshold (percentage)
    int dkgInterval;    // Blocks between DKG sessions
    int dkgPhaseBlocks; // Blocks per DKG phase
    int signingActiveQuorumCount; // Number of active quorums
};

// Get parameters for a quorum type
const LLMQParams& GetLLMQParams(LLMQType type);

/**
 * CQuorumMember - A member of a quorum
 */
struct CQuorumMember {
    uint256 proTxHash;
    CBLSPublicKey pubKeyOperator;
    bool valid{true};
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(proTxHash);
        READWRITE(pubKeyOperator);
        READWRITE(valid);
    }
};

/**
 * CQuorumSnapshot - State of a quorum at a specific height
 */
class CQuorumSnapshot
{
public:
    LLMQType llmqType{LLMQType::LLMQ_NONE};
    uint256 quorumHash;              // Hash identifying this quorum
    int quorumHeight;                // Height when quorum was formed
    std::vector<bool> activeMembers; // Bitmask of active members
    std::vector<bool> skipList;      // Members to skip (PoSe banned etc)
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(llmqType);
        READWRITE(quorumHash);
        READWRITE(quorumHeight);
        READWRITE(activeMembers);
        READWRITE(skipList);
    }
};

/**
 * CQuorum - A Long Living Masternode Quorum
 */
class CQuorum
{
public:
    LLMQType llmqType{LLMQType::LLMQ_NONE};
    uint256 quorumHash;
    int quorumIndex{0};
    int quorumHeight{-1};
    
    // Members
    std::vector<CQuorumMember> members;
    
    // Aggregated public key for the quorum (threshold public key)
    CBLSPublicKey quorumPublicKey;
    
    // Secret key share (only if we're a member)
    // Note: In production, this would be from DKG, not stored directly
    mutable std::unique_ptr<CBLSSecretKey> skShare;
    
    // Validity
    bool fValid{false};
    int validMemberCount{0};
    
    // Cached member set for fast lookup
    mutable std::set<uint256> memberProTxHashes;
    mutable bool membersCached{false};
    
public:
    CQuorum() = default;
    
    bool IsValid() const { return fValid; }
    int GetMemberIndex(const uint256& proTxHash) const;
    bool IsMember(const uint256& proTxHash) const;
    
    // Get the active member public keys
    std::vector<CBLSPublicKey> GetMemberPublicKeys() const;
    
    // Signing threshold
    int GetThreshold() const;
    int GetMinSize() const;
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(llmqType);
        READWRITE(quorumHash);
        READWRITE(quorumIndex);
        READWRITE(quorumHeight);
        READWRITE(members);
        READWRITE(quorumPublicKey);
        READWRITE(fValid);
        READWRITE(validMemberCount);
    }
    
    std::string ToString() const;
};

using CQuorumPtr = std::shared_ptr<CQuorum>;
using CQuorumCPtr = std::shared_ptr<const CQuorum>;

/**
 * CRecoveredSig - A threshold-recovered signature from a quorum
 */
class CRecoveredSig
{
public:
    LLMQType llmqType{LLMQType::LLMQ_NONE};
    uint256 quorumHash;
    uint256 id;           // What is being signed (e.g., txid for InstantSend)
    uint256 msgHash;      // The message hash that was signed
    CBLSSignature sig;    // The recovered signature
    
    // Cached hash
    mutable uint256 hash;
    mutable bool hashCached{false};
    
public:
    CRecoveredSig() = default;
    
    uint256 GetHash() const;
    
    // Build the message hash for signing
    uint256 BuildSignHash() const;
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(llmqType);
        READWRITE(quorumHash);
        READWRITE(id);
        READWRITE(msgHash);
        READWRITE(sig);
    }
    
    std::string ToString() const;
};

/**
 * CQuorumManager - Manages quorum lifecycle and selection
 */
class CQuorumManager
{
private:
    mutable CCriticalSection cs;
    
    // Cached quorums by type and hash
    std::map<std::pair<LLMQType, uint256>, CQuorumCPtr> quorumCache;
    
    // Active quorums per type (most recent first)
    std::map<LLMQType, std::vector<CQuorumCPtr>> activeQuorums;
    
    // Our node's proTxHash (if we're a masternode)
    uint256 myProTxHash;
    
public:
    CQuorumManager();
    
    // Set our identity
    void SetMyProTxHash(const uint256& _proTxHash);
    
    // Build quorum for a given height
    CQuorumCPtr BuildQuorum(LLMQType type, const CBlockIndex* pindex);
    
    // Get quorum by hash
    CQuorumCPtr GetQuorum(LLMQType type, const uint256& quorumHash) const;
    
    // Get active signing quorums
    std::vector<CQuorumCPtr> GetActiveQuorums(LLMQType type) const;
    
    // Select the best quorum for signing at a given height
    CQuorumCPtr SelectQuorumForSigning(LLMQType type, const CBlockIndex* pindex, 
                                        const uint256& selectionHash) const;
    
    // Process a new block
    void UpdatedBlockTip(const CBlockIndex* pindex);
    
    // Check if we're a member of a quorum
    bool IsQuorumMember(LLMQType type, const uint256& quorumHash) const;
    
    // Get our secret key share for a quorum (if we're a member)
    bool GetSecretKeyShare(LLMQType type, const uint256& quorumHash,
                           CBLSSecretKey& skShareOut) const;

private:
    // Deterministically select members for a quorum
    std::vector<CDeterministicMNCPtr> SelectQuorumMembers(
        LLMQType type, 
        const CBlockIndex* pindex) const;
    
    // Score a masternode for quorum selection
    uint256 CalcMemberScore(const CDeterministicMNCPtr& mn, 
                            const uint256& quorumModifier) const;
};

/**
 * CSigningManager - Manages signature sessions
 */
class CSigningManager
{
private:
    mutable CCriticalSection cs;
    
    // Pending signature shares we've received
    std::map<uint256, std::map<uint256, CBLSSignature>> sigShares; // id -> (proTxHash -> sig)
    
    // Recovered signatures
    std::map<uint256, CRecoveredSig> recoveredSigs;
    
    // Reference to quorum manager
    CQuorumManager& quorumManager;
    
public:
    explicit CSigningManager(CQuorumManager& _quorumManager);
    
    // Sign a message (if we're a quorum member)
    bool AsyncSign(LLMQType type, const uint256& id, const uint256& msgHash);
    
    // Process a signature share from another member
    bool ProcessSigShare(const uint256& quorumHash, const uint256& id,
                         const uint256& proTxHash, const CBLSSignature& sigShare);
    
    // Try to recover a signature
    bool TryRecoverSignature(LLMQType type, const uint256& id, const uint256& msgHash,
                             CRecoveredSig& recSigOut);
    
    // Check if we have a recovered signature
    bool GetRecoveredSig(const uint256& id, CRecoveredSig& recSigOut) const;
    
    // Verify a recovered signature
    bool VerifyRecoveredSig(const CRecoveredSig& recSig) const;
    
    // Cleanup old sessions
    void Cleanup(int currentHeight);
};

// Global instances
extern std::unique_ptr<CQuorumManager> quorumManager;
extern std::unique_ptr<CSigningManager> signingManager;

// Initialization
void InitLLMQ();
void StopLLMQ();

} // namespace llmq

#endif // MYNTA_LLMQ_QUORUMS_H

