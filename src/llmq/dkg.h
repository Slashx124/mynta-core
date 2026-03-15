// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MYNTA_LLMQ_DKG_H
#define MYNTA_LLMQ_DKG_H

#include "bls/bls.h"
#include "evo/deterministicmns.h"
#include "llmq/quorums.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"
#include "consensus/validation.h"

#include <atomic>
#include <map>
#include <memory>
#include <set>
#include <vector>

class CBlockIndex;

namespace llmq {

// Forward declarations
class CQuorum;
class CQuorumManager;

/**
 * Distributed Key Generation (DKG) Protocol for LLMQ
 * 
 * Based on Joint-Feldman DKG with SCRAPE verification
 * 
 * Phases:
 * 1. CONTRIBUTION: Each member generates a secret polynomial and broadcasts
 *    encrypted shares to other members along with commitments
 * 2. COMPLAINT: Members verify received shares against commitments and
 *    broadcast complaints for invalid shares
 * 3. JUSTIFICATION: Members who received complaints broadcast the actual
 *    shares to prove they were valid
 * 4. COMMITMENT: Members broadcast their final commitments
 * 5. FINALIZATION: Aggregate commitments to derive quorum public key
 * 
 * Security Properties:
 * - Threshold: t-of-n scheme where t = ceil(n * threshold_percent / 100)
 * - Secrecy: No subset of < t members can recover the secret
 * - Robustness: Protocol succeeds if >= t honest members
 * - Verifiability: All operations are publicly verifiable
 */

// DKG Phase enumeration
enum class DKGPhase : uint8_t {
    IDLE = 0,
    INITIALIZATION = 1,
    CONTRIBUTION = 2,
    COMPLAINT = 3,
    JUSTIFICATION = 4,
    COMMITMENT = 5,
    FINALIZATION = 6,
    DKG_ERROR = 255  // Cannot use 'ERROR' - conflicts with Windows macro
};

std::string DKGPhaseToString(DKGPhase phase);

/**
 * CDKGContribution - A member's contribution in the DKG protocol
 * 
 * Contains:
 * - Commitments to the secret polynomial coefficients (verification vector)
 * - Encrypted secret shares for each other member
 */
class CDKGContribution
{
public:
    uint256 quorumHash;
    uint256 proTxHash;              // Member who created this contribution
    uint16_t memberIndex{0};        // Member's index in the quorum
    
    // Verification vector: commitments to polynomial coefficients
    // vvec[i] = g1 * coeff[i] where coeff[i] is the i-th coefficient
    std::vector<CBLSPublicKey> vvec;
    
    // Encrypted secret shares for each member
    // encryptedShares[j] = Encrypt(pk_j, s_i(j)) where s_i is member i's polynomial
    std::vector<std::vector<uint8_t>> encryptedShares;
    
    // Signature over the contribution (proves authenticity)
    CBLSSignature sig;
    
    // Cached hash (thread-safe)
    mutable uint256 hash;
    mutable std::atomic<bool> hashCached{false};

public:
    CDKGContribution() = default;
    CDKGContribution(const CDKGContribution& o)
        : quorumHash(o.quorumHash), proTxHash(o.proTxHash), memberIndex(o.memberIndex),
          vvec(o.vvec), encryptedShares(o.encryptedShares), sig(o.sig),
          hash(), hashCached(false) {}
    CDKGContribution& operator=(const CDKGContribution& o)
    {
        if (this != &o) {
            quorumHash = o.quorumHash; proTxHash = o.proTxHash; memberIndex = o.memberIndex;
            vvec = o.vvec; encryptedShares = o.encryptedShares; sig = o.sig;
            hash = uint256(); hashCached.store(false, std::memory_order_relaxed);
        }
        return *this;
    }
    CDKGContribution(CDKGContribution&& o) noexcept
        : quorumHash(std::move(o.quorumHash)), proTxHash(std::move(o.proTxHash)),
          memberIndex(o.memberIndex), vvec(std::move(o.vvec)),
          encryptedShares(std::move(o.encryptedShares)), sig(std::move(o.sig)),
          hash(), hashCached(false) {}
    CDKGContribution& operator=(CDKGContribution&& o) noexcept
    {
        if (this != &o) {
            quorumHash = std::move(o.quorumHash); proTxHash = std::move(o.proTxHash);
            memberIndex = o.memberIndex; vvec = std::move(o.vvec);
            encryptedShares = std::move(o.encryptedShares); sig = std::move(o.sig);
            hash = uint256(); hashCached.store(false, std::memory_order_relaxed);
        }
        return *this;
    }

    uint256 GetHash() const;
    uint256 GetSignHash() const;
    
    bool IsValid() const;
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(quorumHash);
        READWRITE(proTxHash);
        READWRITE(memberIndex);
        READWRITE(vvec);
        READWRITE(encryptedShares);
        READWRITE(sig);
    }
    
    std::string ToString() const;
};

/**
 * CDKGComplaint - A complaint about an invalid contribution
 */
class CDKGComplaint
{
public:
    uint256 quorumHash;
    uint256 proTxHash;              // Member filing the complaint
    uint16_t memberIndex{0};
    
    // Bitset of members whose contributions are invalid
    // badMembers[i] = true means member i's share to us was invalid
    std::vector<bool> badMembers;
    
    CBLSSignature sig;

public:
    CDKGComplaint() = default;
    
    uint256 GetHash() const;
    uint256 GetSignHash() const;
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(quorumHash);
        READWRITE(proTxHash);
        READWRITE(memberIndex);
        READWRITE(badMembers);
        READWRITE(sig);
    }
};

/**
 * CDKGJustification - Response to a complaint (reveals the share)
 */
class CDKGJustification
{
public:
    uint256 quorumHash;
    uint256 proTxHash;              // Member providing justification
    uint16_t memberIndex{0};
    
    // Map of complainer index -> revealed share
    // If the revealed share verifies against the commitment, the complaint was false
    std::map<uint16_t, std::vector<uint8_t>> contributions;
    
    CBLSSignature sig;

public:
    CDKGJustification() = default;
    
    uint256 GetHash() const;
    uint256 GetSignHash() const;
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(quorumHash);
        READWRITE(proTxHash);
        READWRITE(memberIndex);
        READWRITE(contributions);
        READWRITE(sig);
    }
};

/**
 * CDKGPrematureCommitment - Early commitment to final share (before complaints resolved)
 */
class CDKGPrematureCommitment
{
public:
    uint256 quorumHash;
    uint256 proTxHash;
    uint16_t memberIndex{0};
    
    // Members we consider valid (based on contributions received)
    std::vector<bool> validMembers;
    
    // The quorum public key we computed
    CBLSPublicKey quorumPublicKey;
    
    // Hash of our secret key share (for verification without revealing)
    uint256 secretKeyShareHash;
    
    CBLSSignature sig;

public:
    CDKGPrematureCommitment() = default;
    
    uint256 GetHash() const;
    uint256 GetSignHash() const;
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(quorumHash);
        READWRITE(proTxHash);
        READWRITE(memberIndex);
        READWRITE(validMembers);
        READWRITE(quorumPublicKey);
        READWRITE(secretKeyShareHash);
        READWRITE(sig);
    }
};

/**
 * CDKGFinalCommitment - Final commitment after all phases complete
 */
class CDKGFinalCommitment
{
public:
    uint256 quorumHash;
    
    // Members who successfully completed DKG
    std::vector<bool> signers;
    std::vector<bool> validMembers;
    
    // The final quorum public key
    CBLSPublicKey quorumPublicKey;
    
    // Verification vector for the quorum (aggregated from valid members)
    std::vector<CBLSPublicKey> quorumVvec;
    
    // Aggregated signature from signers confirming the commitment
    CBLSSignature membersSig;
    
    // Cached hash (thread-safe)
    mutable uint256 hash;
    mutable std::atomic<bool> hashCached{false};

public:
    CDKGFinalCommitment() = default;
    CDKGFinalCommitment(const CDKGFinalCommitment& o)
        : quorumHash(o.quorumHash), signers(o.signers), validMembers(o.validMembers),
          quorumPublicKey(o.quorumPublicKey), quorumVvec(o.quorumVvec),
          membersSig(o.membersSig), hash(), hashCached(false) {}
    CDKGFinalCommitment& operator=(const CDKGFinalCommitment& o)
    {
        if (this != &o) {
            quorumHash = o.quorumHash; signers = o.signers; validMembers = o.validMembers;
            quorumPublicKey = o.quorumPublicKey; quorumVvec = o.quorumVvec;
            membersSig = o.membersSig;
            hash = uint256(); hashCached.store(false, std::memory_order_relaxed);
        }
        return *this;
    }
    CDKGFinalCommitment(CDKGFinalCommitment&& o) noexcept
        : quorumHash(std::move(o.quorumHash)), signers(std::move(o.signers)),
          validMembers(std::move(o.validMembers)),
          quorumPublicKey(std::move(o.quorumPublicKey)),
          quorumVvec(std::move(o.quorumVvec)),
          membersSig(std::move(o.membersSig)), hash(), hashCached(false) {}
    CDKGFinalCommitment& operator=(CDKGFinalCommitment&& o) noexcept
    {
        if (this != &o) {
            quorumHash = std::move(o.quorumHash); signers = std::move(o.signers);
            validMembers = std::move(o.validMembers);
            quorumPublicKey = std::move(o.quorumPublicKey);
            quorumVvec = std::move(o.quorumVvec);
            membersSig = std::move(o.membersSig);
            hash = uint256(); hashCached.store(false, std::memory_order_relaxed);
        }
        return *this;
    }

    uint256 GetHash() const;
    uint256 GetSignHash() const;
    
    // Count signers/valid members
    size_t CountSigners() const;
    size_t CountValidMembers() const;
    
    // Verify the commitment.  nHeight is the block height at which this
    // commitment is being validated so the correct threshold rules apply.
    bool Verify(const std::vector<CDeterministicMNCPtr>& members, bool checkSigs = true,
                LLMQType llmqType = LLMQType::LLMQ_50_60, int nHeight = 0) const;
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(quorumHash);
        READWRITE(signers);
        READWRITE(validMembers);
        READWRITE(quorumPublicKey);
        READWRITE(quorumVvec);
        READWRITE(membersSig);
    }
    
    std::string ToString() const;
};

/**
 * CDKGSession - Manages a single DKG session for a quorum
 */
class CDKGSession
{
private:
    mutable CCriticalSection cs;
    
    // Session parameters
    uint256 quorumHash;
    int quorumHeight{0};
    LLMQType llmqType{LLMQType::LLMQ_NONE};
    size_t quorumSize{0};
    size_t threshold{0};
    
    // Our identity
    uint256 myProTxHash;
    int myMemberIndex{-1};
    
    // Our operator key pair for ECDH (required for secure share encryption)
    // This MUST be set via SetOperatorKey() before creating contributions
    std::unique_ptr<CBLSSecretKey> myOperatorSecretKey;
    CBLSPublicKey myOperatorPublicKey;
    
    // Members in this quorum
    std::vector<CDeterministicMNCPtr> members;
    std::map<uint256, size_t> membersMap;  // proTxHash -> index
    
    // Our secret polynomial coefficients (only we know these)
    std::vector<CBLSSecretKey> secretCoefficients;
    
    // Our verification vector (public commitments to coefficients)
    std::vector<CBLSPublicKey> myVvec;
    
    // Secret shares we computed for each member
    std::map<size_t, CBLSSecretKey> secretShares;  // memberIndex -> share
    
    // Received contributions
    std::map<uint256, CDKGContribution> receivedContributions;
    
    // Decrypted shares we received from others
    std::map<size_t, CBLSSecretKey> receivedShares;  // memberIndex -> share
    
    // Verification vectors from others
    std::map<size_t, std::vector<CBLSPublicKey>> receivedVvecs;
    
    // Members with valid contributions
    std::set<size_t> validMembers;
    
    // Complaints
    std::map<uint256, CDKGComplaint> receivedComplaints;
    std::set<size_t> complainedMembers;  // Members we complained about
    std::set<size_t> badMembers;  // Members proven to be bad
    
    // Justifications
    std::map<uint256, CDKGJustification> receivedJustifications;
    
    // Premature commitments
    std::map<uint256, CDKGPrematureCommitment> receivedPrematureCommitments;
    
    // Final results
    CBLSSecretKey secretKeyShare;  // Our final secret key share
    CBLSPublicKey quorumPublicKey; // The quorum's public key
    std::vector<CBLSPublicKey> quorumVvec;  // The quorum's verification vector
    
    // Phase tracking
    DKGPhase phase{DKGPhase::IDLE};
    int phaseStartHeight{0};
    
    // Timing
    int64_t sessionStartTime{0};

public:
    CDKGSession() = default;
    ~CDKGSession();
    
    // Prevent copying (contains secret key)
    CDKGSession(const CDKGSession&) = delete;
    CDKGSession& operator=(const CDKGSession&) = delete;
    
    // Initialize the session
    bool Init(const uint256& _quorumHash, int _quorumHeight, LLMQType _llmqType,
              const std::vector<CDeterministicMNCPtr>& _members,
              const uint256& _myProTxHash);
    
    /**
     * Set our operator secret key for ECDH-based share encryption.
     * MUST be called before CreateContribution() if we are a quorum member.
     * 
     * SECURITY: This key is used to compute ECDH shared secrets with other
     * quorum members. The key must correspond to the operator public key
     * registered in our masternode record.
     * 
     * @param operatorSecretKey Our operator BLS secret key
     * @return true if the key was accepted (valid and matches our public key)
     */
    bool SetOperatorKey(const CBLSSecretKey& operatorSecretKey);
    
    /**
     * Check if operator key is set (required for secure DKG participation).
     */
    bool HasOperatorKey() const;
    
    // Check if we're a member
    bool IsOurTurn() const { return myMemberIndex >= 0; }
    int GetMyMemberIndex() const { return myMemberIndex; }
    
    // Phase management
    DKGPhase GetPhase() const { return phase; }
    bool AdvancePhase(int currentHeight);
    
    // Phase 1: Contribution
    CDKGContribution CreateContribution();
    bool ProcessContribution(const CDKGContribution& contribution, CValidationState& state);
    
    // Phase 2: Complaint
    CDKGComplaint CreateComplaint();
    bool ProcessComplaint(const CDKGComplaint& complaint, CValidationState& state);
    
    // Phase 3: Justification
    CDKGJustification CreateJustification();
    bool ProcessJustification(const CDKGJustification& justification, CValidationState& state);
    
    // Phase 4: Premature Commitment
    CDKGPrematureCommitment CreatePrematureCommitment();
    bool ProcessPrematureCommitment(const CDKGPrematureCommitment& commitment, CValidationState& state);
    
    // Phase 5: Final Commitment
    CDKGFinalCommitment CreateFinalCommitment();
    bool ProcessFinalCommitment(const CDKGFinalCommitment& commitment, CValidationState& state);
    
    // Get results
    bool GetSecretKeyShare(CBLSSecretKey& skShareOut) const;
    bool GetQuorumPublicKey(CBLSPublicKey& pkOut) const;
    const std::vector<CBLSPublicKey>& GetQuorumVvec() const { return quorumVvec; }
    
    // Verify a member's share against their verification vector
    static bool VerifyShare(const CBLSSecretKey& share, 
                           const std::vector<CBLSPublicKey>& vvec,
                           size_t memberIndex);
    
    // Status
    bool IsComplete() const { return phase == DKGPhase::FINALIZATION && !quorumPublicKey.IsNull(); }
    std::string ToString() const;

private:
    // Generate secret polynomial of degree (threshold - 1)
    void GenerateSecretPolynomial();
    
    // Evaluate polynomial at a point
    CBLSSecretKey EvaluatePolynomial(size_t x) const;
    
    // Compute verification vector from coefficients
    void ComputeVerificationVector();
    
    // Encrypt a share for a member using authenticated encryption
    // Both sender and receiver can derive the same key independently
    std::vector<uint8_t> EncryptShare(const CBLSSecretKey& share, 
                                       const CBLSPublicKey& targetPubKey,
                                       size_t targetMemberIndex) const;
    
    // Decrypt a share meant for us using authenticated encryption
    // Returns false if authentication fails (share was tampered with)
    bool DecryptShare(const std::vector<uint8_t>& encrypted,
                      size_t senderMemberIndex,
                      CBLSSecretKey& shareOut) const;
    
    // Aggregate verification vectors from valid members
    void AggregateVerificationVectors();
    
    // Compute final secret key share
    void ComputeFinalSecretKeyShare();
    
    // Compute quorum public key from aggregated vvec
    void ComputeQuorumPublicKey();
};

/**
 * CDKGSessionManager - Manages DKG sessions across quorum types
 */
class CDKGSessionManager
{
private:
    mutable CCriticalSection cs;
    
    // Active sessions by quorum hash
    std::map<uint256, std::shared_ptr<CDKGSession>> activeSessions;
    
    // Completed sessions (final commitments)
    std::map<uint256, CDKGFinalCommitment> finalCommitments;
    
    // Reference to quorum manager
    CQuorumManager& quorumManager;
    
    // Our identity
    uint256 myProTxHash;
    
    // Our operator BLS secret key (required for DKG participation)
    std::unique_ptr<CBLSSecretKey> myOperatorKey;
    
    // Rate limiting to prevent DoS attacks
    // Tracks message counts per member within a time window
    struct RateLimitEntry {
        int64_t windowStart{0};
        int messageCount{0};
    };
    std::map<uint256, RateLimitEntry> rateLimitMap;  // proTxHash -> entry
    static const int MAX_MESSAGES_PER_WINDOW = 100;  // Max messages per member per window
    static const int64_t RATE_LIMIT_WINDOW = 60;     // Window size in seconds
    
    // Check if a member is rate limited
    bool IsRateLimited(const uint256& proTxHash);

public:
    explicit CDKGSessionManager(CQuorumManager& _quorumManager);
    
    // Set our identity
    void SetMyProTxHash(const uint256& _proTxHash);
    
    // Set our operator key (required for DKG participation)
    // Returns true if successful, false if key is invalid
    bool SetMyOperatorKey(const CBLSSecretKey& operatorKey);
    
    // Check if we have an operator key configured
    bool HasOperatorKey() const;
    
    // Start a new DKG session
    bool StartSession(LLMQType llmqType, const CBlockIndex* pindex);
    
    // Process DKG messages
    bool ProcessContribution(const CDKGContribution& contribution, CValidationState& state);
    bool ProcessComplaint(const CDKGComplaint& complaint, CValidationState& state);
    bool ProcessJustification(const CDKGJustification& justification, CValidationState& state);
    bool ProcessPrematureCommitment(const CDKGPrematureCommitment& commitment, CValidationState& state);
    bool ProcessFinalCommitment(const CDKGFinalCommitment& commitment, CValidationState& state);
    
    // Get session for a quorum
    std::shared_ptr<CDKGSession> GetSession(const uint256& quorumHash) const;
    
    // Get final commitment for a quorum
    bool GetFinalCommitment(const uint256& quorumHash, CDKGFinalCommitment& commitmentOut) const;
    
    // Get secret key share for a quorum (if we participated)
    bool GetSecretKeyShare(const uint256& quorumHash, CBLSSecretKey& skShareOut) const;
    
    // Check if DKG is complete for a quorum
    bool IsDKGComplete(const uint256& quorumHash) const;
    
    // Update on new block
    void UpdatedBlockTip(const CBlockIndex* pindex);
    
    // Cleanup old sessions
    void Cleanup();

private:
    // Create DKG messages for broadcast
    void CreateAndBroadcastContributions();
    void CreateAndBroadcastComplaints();
    void CreateAndBroadcastJustifications();
    void CreateAndBroadcastPrematureCommitments();
    void CreateAndBroadcastFinalCommitments();
};

// Global instance
extern std::unique_ptr<CDKGSessionManager> dkgSessionManager;

// Initialization
void InitDKG(CQuorumManager& quorumManager);
void StopDKG();

} // namespace llmq

#endif // MYNTA_LLMQ_DKG_H
