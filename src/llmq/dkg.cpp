// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "llmq/dkg.h"
#include "llmq/quorums.h"
#include "chain.h"
#include "chainparams.h"
#include "crypto/hmac_sha256.h"
#include "hash.h"
#include "random.h"
#include "support/cleanse.h"
#include "util.h"
#include "validation.h"

#include <algorithm>
#include <sstream>

// Use BLST for low-level BLS operations
#include "bls/blst/bindings/blst.h"

namespace llmq {

// Global instance
std::unique_ptr<CDKGSessionManager> dkgSessionManager;

// ============================================================================
// Utility Functions
// ============================================================================

std::string DKGPhaseToString(DKGPhase phase)
{
    switch (phase) {
        case DKGPhase::IDLE: return "IDLE";
        case DKGPhase::INITIALIZATION: return "INITIALIZATION";
        case DKGPhase::CONTRIBUTION: return "CONTRIBUTION";
        case DKGPhase::COMPLAINT: return "COMPLAINT";
        case DKGPhase::JUSTIFICATION: return "JUSTIFICATION";
        case DKGPhase::COMMITMENT: return "COMMITMENT";
        case DKGPhase::FINALIZATION: return "FINALIZATION";
        case DKGPhase::DKG_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Authenticated Encryption for DKG Share Distribution
// 
// SECURITY ARCHITECTURE:
// 
// DKG shares are encrypted using a two-layer approach:
// 1. ECDH Key Exchange: Compute shared secret using BLS key pairs
//    - Sender computes: shared = sk_sender * pk_receiver
//    - Receiver computes: shared = sk_receiver * pk_sender
//    - Both get the same shared secret (sk_sender * sk_receiver * G1)
// 
// 2. Authenticated Encryption: ChaCha20 + HMAC-SHA256 (Encrypt-then-MAC)
//    - The shared secret is used to derive encryption and MAC keys
//    - Random nonce prevents replay attacks
//    - HMAC provides authenticity and integrity
//
// This ensures that only the intended recipient can decrypt the share,
// and any tampering is detected.
// ============================================================================

#include "crypto/chacha20.h"
#include "crypto/hmac_sha256.h"

// Authentication tag size (HMAC-SHA256 truncated to 16 bytes for efficiency)
static const size_t DKG_AUTH_TAG_SIZE = 16;
// Nonce size for ChaCha20
static const size_t DKG_NONCE_SIZE = 8;

/**
 * DeriveShareEncryptionKeyECDH - Derive encryption key using proper ECDH
 * 
 * This is the SECURE version that uses actual cryptographic key exchange.
 * Both sender and receiver can independently compute the same shared secret
 * using their own secret key and the other party's public key.
 * 
 * @param ourSecretKey Our BLS secret key
 * @param theirPublicKey Their BLS public key
 * @param quorumHash Quorum identifier for domain separation
 * @param senderIndex Sender's member index
 * @param receiverIndex Receiver's member index
 * @return 32-byte symmetric encryption key, or null uint256 on failure
 */
static uint256 DeriveShareEncryptionKeyECDH(const CBLSSecretKey& ourSecretKey,
                                             const CBLSPublicKey& theirPublicKey,
                                             const uint256& quorumHash,
                                             size_t senderIndex,
                                             size_t receiverIndex)
{
    // Build context for ECDH computation
    // This binds the shared secret to this specific quorum and member pair
    CHashWriter contextHw(SER_GETHASH, 0);
    contextHw << std::string("DKG_ECDH_CONTEXT_V3");
    contextHw << quorumHash;
    // Order indices canonically to ensure both parties derive same context
    if (senderIndex < receiverIndex) {
        contextHw << static_cast<uint64_t>(senderIndex);
        contextHw << static_cast<uint64_t>(receiverIndex);
    } else {
        contextHw << static_cast<uint64_t>(receiverIndex);
        contextHw << static_cast<uint64_t>(senderIndex);
    }
    uint256 contextHash = contextHw.GetHash();
    std::vector<uint8_t> context(contextHash.begin(), contextHash.end());
    
    // Compute ECDH shared secret
    CBLSECDHSecret ecdhSecret;
    if (!ecdhSecret.Compute(ourSecretKey, theirPublicKey, context)) {
        LogPrintf("DeriveShareEncryptionKeyECDH: ECDH computation failed\n");
        return uint256();
    }
    
    // Derive encryption key from the shared secret
    return ecdhSecret.DeriveKey("dkg_share_encryption", context);
}

/**
 * AEADEncrypt - Authenticated encryption using ChaCha20 + HMAC-SHA256
 * 
 * Format: nonce (8 bytes) || ciphertext || tag (16 bytes)
 * 
 * @param plaintext Data to encrypt
 * @param key 32-byte encryption key
 * @param contextData Additional data to authenticate (but not encrypt)
 * @return Encrypted data with authentication tag, or empty on failure
 */
static std::vector<uint8_t> AEADEncrypt(const std::vector<uint8_t>& plaintext,
                                         const uint256& key,
                                         const std::vector<uint8_t>& contextData = {})
{
    if (plaintext.empty()) {
        return {};
    }
    
    // Generate random nonce
    std::vector<uint8_t> nonce(DKG_NONCE_SIZE);
    GetStrongRandBytes(nonce.data(), DKG_NONCE_SIZE);
    
    // Derive encryption key and MAC key from master key
    CHashWriter ekw(SER_GETHASH, 0);
    ekw << std::string("DKG_ENC_KEY");
    ekw << key;
    ekw << nonce;
    uint256 encKey = ekw.GetHash();
    
    CHashWriter mkw(SER_GETHASH, 0);
    mkw << std::string("DKG_MAC_KEY");
    mkw << key;
    mkw << nonce;
    uint256 macKey = mkw.GetHash();
    
    // Encrypt using ChaCha20
    ChaCha20 cipher(encKey.begin(), 32);
    uint64_t iv = 0;
    for (size_t i = 0; i < DKG_NONCE_SIZE && i < 8; i++) {
        iv |= static_cast<uint64_t>(nonce[i]) << (i * 8);
    }
    cipher.SetIV(iv);
    
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> keystream(plaintext.size());
    cipher.Output(keystream.data(), keystream.size());
    
    for (size_t i = 0; i < plaintext.size(); i++) {
        ciphertext[i] = plaintext[i] ^ keystream[i];
    }
    
    // Compute MAC over (contextData || nonce || ciphertext) - Encrypt-then-MAC
    ::CHMAC_SHA256 hmac(macKey.begin(), 32);
    if (!contextData.empty()) {
        hmac.Write(contextData.data(), contextData.size());
    }
    hmac.Write(nonce.data(), nonce.size());
    hmac.Write(ciphertext.data(), ciphertext.size());
    
    uint8_t fullTag[::CHMAC_SHA256::OUTPUT_SIZE];
    hmac.Finalize(fullTag);
    
    // Build output: nonce || ciphertext || tag (truncated to 16 bytes)
    std::vector<uint8_t> result;
    result.reserve(DKG_NONCE_SIZE + ciphertext.size() + DKG_AUTH_TAG_SIZE);
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), fullTag, fullTag + DKG_AUTH_TAG_SIZE);
    
    // Clear sensitive data
    memory_cleanse(keystream.data(), keystream.size());
    memory_cleanse(fullTag, sizeof(fullTag));
    
    return result;
}

/**
 * AEADDecrypt - Authenticated decryption using ChaCha20 + HMAC-SHA256
 * 
 * @param ciphertext Encrypted data (nonce || ciphertext || tag)
 * @param key 32-byte decryption key
 * @param plaintext Output: decrypted data
 * @param contextData Additional authenticated data (must match encryption)
 * @return true if decryption and authentication succeeded
 */
static bool AEADDecrypt(const std::vector<uint8_t>& ciphertext,
                        const uint256& key,
                        std::vector<uint8_t>& plaintext,
                        const std::vector<uint8_t>& contextData = {})
{
    // Minimum size: nonce + 1 byte + tag
    if (ciphertext.size() < DKG_NONCE_SIZE + 1 + DKG_AUTH_TAG_SIZE) {
        return false;
    }
    
    // Extract components
    std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + DKG_NONCE_SIZE);
    std::vector<uint8_t> encData(ciphertext.begin() + DKG_NONCE_SIZE, 
                                  ciphertext.end() - DKG_AUTH_TAG_SIZE);
    std::vector<uint8_t> receivedTag(ciphertext.end() - DKG_AUTH_TAG_SIZE, ciphertext.end());
    
    // Derive keys
    CHashWriter ekw(SER_GETHASH, 0);
    ekw << std::string("DKG_ENC_KEY");
    ekw << key;
    ekw << nonce;
    uint256 encKey = ekw.GetHash();
    
    CHashWriter mkw(SER_GETHASH, 0);
    mkw << std::string("DKG_MAC_KEY");
    mkw << key;
    mkw << nonce;
    uint256 macKey = mkw.GetHash();
    
    // Verify MAC first (before decryption) - prevents oracle attacks
    ::CHMAC_SHA256 hmac(macKey.begin(), 32);
    if (!contextData.empty()) {
        hmac.Write(contextData.data(), contextData.size());
    }
    hmac.Write(nonce.data(), nonce.size());
    hmac.Write(encData.data(), encData.size());
    
    uint8_t computedTag[::CHMAC_SHA256::OUTPUT_SIZE];
    hmac.Finalize(computedTag);
    
    // Constant-time comparison of tags
    bool tagValid = true;
    for (size_t i = 0; i < DKG_AUTH_TAG_SIZE; i++) {
        tagValid &= (computedTag[i] == receivedTag[i]);
    }
    
    memory_cleanse(computedTag, sizeof(computedTag));
    
    if (!tagValid) {
        LogPrintf("AEADDecrypt: authentication failed\n");
        return false;
    }
    
    // Decrypt using ChaCha20
    ChaCha20 cipher(encKey.begin(), 32);
    uint64_t iv = 0;
    for (size_t i = 0; i < DKG_NONCE_SIZE && i < 8; i++) {
        iv |= static_cast<uint64_t>(nonce[i]) << (i * 8);
    }
    cipher.SetIV(iv);
    
    std::vector<uint8_t> keystream(encData.size());
    cipher.Output(keystream.data(), keystream.size());
    
    plaintext.resize(encData.size());
    for (size_t i = 0; i < encData.size(); i++) {
        plaintext[i] = encData[i] ^ keystream[i];
    }
    
    memory_cleanse(keystream.data(), keystream.size());
    
    return true;
}

// ============================================================================
// CDKGContribution Implementation
// ============================================================================

uint256 CDKGContribution::GetHash() const
{
    if (!hashCached.load(std::memory_order_acquire)) {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << *this;
        hash = hw.GetHash();
        hashCached.store(true, std::memory_order_release);
    }
    return hash;
}

uint256 CDKGContribution::GetSignHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("DKG_CONTRIBUTION");
    hw << quorumHash;
    hw << proTxHash;
    hw << memberIndex;
    hw << vvec;
    hw << encryptedShares;
    return hw.GetHash();
}

bool CDKGContribution::IsValid() const
{
    if (quorumHash.IsNull() || proTxHash.IsNull()) return false;
    if (vvec.empty()) return false;
    if (encryptedShares.empty()) return false;
    
    // Check all vvec elements are valid
    for (const auto& pk : vvec) {
        if (!pk.IsValid()) return false;
    }
    
    return sig.IsValid();
}

std::string CDKGContribution::ToString() const
{
    std::ostringstream ss;
    ss << "CDKGContribution("
       << "quorum=" << quorumHash.ToString().substr(0, 16)
       << ", member=" << proTxHash.ToString().substr(0, 16)
       << ", idx=" << memberIndex
       << ", vvec_size=" << vvec.size()
       << ", shares=" << encryptedShares.size()
       << ")";
    return ss.str();
}

// ============================================================================
// CDKGComplaint Implementation
// ============================================================================

uint256 CDKGComplaint::GetHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << *this;
    return hw.GetHash();
}

uint256 CDKGComplaint::GetSignHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("DKG_COMPLAINT");
    hw << quorumHash;
    hw << proTxHash;
    hw << memberIndex;
    hw << badMembers;
    return hw.GetHash();
}

// ============================================================================
// CDKGJustification Implementation
// ============================================================================

uint256 CDKGJustification::GetHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << *this;
    return hw.GetHash();
}

uint256 CDKGJustification::GetSignHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("DKG_JUSTIFICATION");
    hw << quorumHash;
    hw << proTxHash;
    hw << memberIndex;
    // Note: contributions map is included for completeness
    for (const auto& [idx, contrib] : contributions) {
        hw << idx;
        hw << contrib;
    }
    return hw.GetHash();
}

// ============================================================================
// CDKGPrematureCommitment Implementation
// ============================================================================

uint256 CDKGPrematureCommitment::GetHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << *this;
    return hw.GetHash();
}

uint256 CDKGPrematureCommitment::GetSignHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("DKG_PREMATURE_COMMITMENT");
    hw << quorumHash;
    hw << proTxHash;
    hw << memberIndex;
    hw << validMembers;
    hw << quorumPublicKey;
    hw << secretKeyShareHash;
    return hw.GetHash();
}

// ============================================================================
// CDKGFinalCommitment Implementation
// ============================================================================

uint256 CDKGFinalCommitment::GetHash() const
{
    if (!hashCached.load(std::memory_order_acquire)) {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << *this;
        hash = hw.GetHash();
        hashCached.store(true, std::memory_order_release);
    }
    return hash;
}

uint256 CDKGFinalCommitment::GetSignHash() const
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("DKG_FINAL_COMMITMENT");
    hw << quorumHash;
    hw << signers;
    hw << validMembers;
    hw << quorumPublicKey;
    hw << quorumVvec;
    return hw.GetHash();
}

size_t CDKGFinalCommitment::CountSigners() const
{
    return std::count(signers.begin(), signers.end(), true);
}

size_t CDKGFinalCommitment::CountValidMembers() const
{
    return std::count(validMembers.begin(), validMembers.end(), true);
}

bool CDKGFinalCommitment::Verify(const std::vector<CDeterministicMNCPtr>& members, bool checkSigs,
                                 LLMQType llmqType, int nHeight) const
{
    if (quorumHash.IsNull()) return false;
    if (signers.size() != members.size()) return false;
    if (validMembers.size() != members.size()) return false;
    if (!quorumPublicKey.IsValid()) return false;
    if (quorumVvec.empty()) return false;
    
    size_t signerCount = CountSigners();
    size_t validCount = CountValidMembers();
    
    // Before nConsensusFixHeight the threshold was always computed against
    // LLMQ_50_60 regardless of the actual quorum type (legacy bug).
    // Preserve that behaviour for commitments created before the gate.
    // Use the explicit nHeight when provided; fall back to chainActive only
    // as a last resort so that block-validation contexts are deterministic
    // regardless of the current tip (important during IBD).
    LLMQType effectiveType = llmqType;
    {
        int checkHeight = nHeight;
        if (checkHeight <= 0) {
            LOCK(cs_main);
            checkHeight = chainActive.Height();
        }
        if (checkHeight < GetParams().GetConsensus().nConsensusFixHeight) {
            effectiveType = LLMQType::LLMQ_50_60;
        }
    }
    const auto& params = GetLLMQParams(effectiveType);
    size_t minSigners = (members.size() * params.threshold + 99) / 100;
    
    if (signerCount < minSigners) {
        LogPrintf("CDKGFinalCommitment::Verify -- not enough signers: %zu < %zu\n", signerCount, minSigners);
        return false;
    }
    
    if (validCount < minSigners) {
        LogPrintf("CDKGFinalCommitment::Verify -- not enough valid members: %zu < %zu\n", validCount, minSigners);
        return false;
    }
    
    if (checkSigs && !membersSig.IsValid()) {
        return false;
    }
    
    if (checkSigs) {
        // Aggregate public keys of signers
        std::vector<CBLSPublicKey> signerPks;
        for (size_t i = 0; i < members.size(); i++) {
            if (signers[i]) {
                CBLSPublicKey opKey;
                if (opKey.SetBytes(members[i]->state.vchOperatorPubKey)) {
                    signerPks.push_back(opKey);
                }
            }
        }
        
        if (signerPks.empty()) return false;
        
        CBLSPublicKey aggPk = CBLSPublicKey::AggregatePublicKeys(signerPks);
        uint256 signHash = GetSignHash();
        
        if (!membersSig.VerifyWithDomain(aggPk, signHash, BLSDomainTags::QUORUM)) {
            LogPrintf("CDKGFinalCommitment::Verify -- signature verification failed\n");
            return false;
        }
    }
    
    return true;
}

std::string CDKGFinalCommitment::ToString() const
{
    std::ostringstream ss;
    ss << "CDKGFinalCommitment("
       << "quorum=" << quorumHash.ToString().substr(0, 16)
       << ", signers=" << CountSigners()
       << ", valid=" << CountValidMembers()
       << ", pk=" << quorumPublicKey.ToString().substr(0, 16)
       << ")";
    return ss.str();
}

// ============================================================================
// CDKGSession Implementation
// ============================================================================

CDKGSession::~CDKGSession()
{
    LOCK(cs);
    // Securely clear operator secret key
    myOperatorSecretKey.reset();
    // Clear secret coefficients
    for (auto& coeff : secretCoefficients) {
        // CBLSSecretKey destructor handles secure cleansing
    }
    secretCoefficients.clear();
    // Clear secret shares
    secretShares.clear();
    receivedShares.clear();
}

bool CDKGSession::Init(const uint256& _quorumHash, int _quorumHeight, LLMQType _llmqType,
                       const std::vector<CDeterministicMNCPtr>& _members,
                       const uint256& _myProTxHash)
{
    LOCK(cs);
    
    quorumHash = _quorumHash;
    quorumHeight = _quorumHeight;
    llmqType = _llmqType;
    members = _members;
    myProTxHash = _myProTxHash;
    
    quorumSize = members.size();
    const auto& params = GetLLMQParams(llmqType);
    threshold = (quorumSize * params.threshold + 99) / 100;
    
    // Build member map
    membersMap.clear();
    myMemberIndex = -1;
    for (size_t i = 0; i < members.size(); i++) {
        membersMap[members[i]->proTxHash] = i;
        if (members[i]->proTxHash == myProTxHash) {
            myMemberIndex = static_cast<int>(i);
            // Get our public key from the masternode record
            myOperatorPublicKey.SetBytes(members[i]->state.vchOperatorPubKey);
        }
    }
    
    // Mark all members as initially valid
    validMembers.clear();
    for (size_t i = 0; i < quorumSize; i++) {
        validMembers.insert(i);
    }
    
    phase = DKGPhase::INITIALIZATION;
    sessionStartTime = GetTime();
    
    LogPrintf("CDKGSession::Init -- quorum=%s, height=%d, members=%zu, threshold=%zu, myIndex=%d\n",
              quorumHash.ToString().substr(0, 16), quorumHeight, quorumSize, threshold, myMemberIndex);
    
    return true;
}

bool CDKGSession::SetOperatorKey(const CBLSSecretKey& operatorSecretKey)
{
    LOCK(cs);
    
    if (!operatorSecretKey.IsValid()) {
        LogPrintf("CDKGSession::SetOperatorKey -- invalid secret key\n");
        return false;
    }
    
    // Verify the key matches our public key
    CBLSPublicKey derivedPubKey = operatorSecretKey.GetPublicKey();
    if (!myOperatorPublicKey.IsValid()) {
        LogPrintf("CDKGSession::SetOperatorKey -- our public key not set (Init not called?)\n");
        return false;
    }
    
    if (derivedPubKey != myOperatorPublicKey) {
        LogPrintf("CDKGSession::SetOperatorKey -- secret key does not match our operator public key\n");
        return false;
    }
    
    // Store the secret key securely
    myOperatorSecretKey = std::make_unique<CBLSSecretKey>();
    myOperatorSecretKey->SetSecretKey(operatorSecretKey.ToBytes());
    
    LogPrint(BCLog::LLMQ, "CDKGSession::SetOperatorKey -- operator key set successfully\n");
    return true;
}

bool CDKGSession::HasOperatorKey() const
{
    LOCK(cs);
    return myOperatorSecretKey && myOperatorSecretKey->IsValid();
}

bool CDKGSession::AdvancePhase(int currentHeight)
{
    LOCK(cs);
    
    const auto& params = GetLLMQParams(llmqType);
    int phaseBlocks = params.dkgPhaseBlocks;
    
    DKGPhase expectedPhase;
    int phaseNum = (currentHeight - quorumHeight) / phaseBlocks;
    
    switch (phaseNum) {
        case 0: expectedPhase = DKGPhase::INITIALIZATION; break;
        case 1: expectedPhase = DKGPhase::CONTRIBUTION; break;
        case 2: expectedPhase = DKGPhase::COMPLAINT; break;
        case 3: expectedPhase = DKGPhase::JUSTIFICATION; break;
        case 4: expectedPhase = DKGPhase::COMMITMENT; break;
        default: expectedPhase = DKGPhase::FINALIZATION; break;
    }
    
    if (phase != expectedPhase) {
        LogPrintf("CDKGSession::AdvancePhase -- %s -> %s at height %d\n",
                  DKGPhaseToString(phase), DKGPhaseToString(expectedPhase), currentHeight);
        phase = expectedPhase;
        phaseStartHeight = currentHeight;
        return true;
    }
    
    return false;
}

void CDKGSession::GenerateSecretPolynomial()
{
    // Generate a random polynomial of degree (threshold - 1)
    // p(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
    
    secretCoefficients.clear();
    secretCoefficients.resize(threshold);
    
    for (size_t i = 0; i < threshold; i++) {
        secretCoefficients[i].MakeNewKey();
    }
    
    LogPrint(BCLog::LLMQ, "CDKGSession::GenerateSecretPolynomial -- generated %zu coefficients\n", threshold);
}

CBLSSecretKey CDKGSession::EvaluatePolynomial(size_t x) const
{
    // Evaluate p(x) = sum(a_i * x^i) for i = 0 to threshold-1
    // Use Horner's method: p(x) = a_0 + x*(a_1 + x*(a_2 + ...))
    
    if (secretCoefficients.empty()) {
        return CBLSSecretKey();
    }
    
    // Convert x to scalar
    blst_scalar xScalar, resultScalar, termScalar;
    
    // Initialize result to highest coefficient
    std::vector<uint8_t> coeffBytes = secretCoefficients[threshold - 1].ToBytes();
    blst_scalar_from_bendian(&resultScalar, coeffBytes.data());
    
    // Convert x to scalar (x is 1-indexed: member 0 evaluates at x=1)
    uint8_t xBytes[32] = {0};
    xBytes[31] = static_cast<uint8_t>(x + 1);  // 1-indexed
    blst_scalar_from_bendian(&xScalar, xBytes);
    
    // Horner's method: result = a_{t-1}; for i = t-2 to 0: result = result * x + a_i
    for (int i = static_cast<int>(threshold) - 2; i >= 0; i--) {
        // result = result * x
        blst_sk_mul_n_check(&resultScalar, &resultScalar, &xScalar);
        
        // result = result + a_i
        std::vector<uint8_t> aiBytes = secretCoefficients[i].ToBytes();
        blst_scalar_from_bendian(&termScalar, aiBytes.data());
        blst_sk_add_n_check(&resultScalar, &resultScalar, &termScalar);
    }
    
    // Convert result back to secret key
    std::vector<uint8_t> resultBytes(32);
    blst_bendian_from_scalar(resultBytes.data(), &resultScalar);
    
    CBLSSecretKey result;
    result.SetSecretKey(resultBytes);
    
    // Clear sensitive data
    memory_cleanse(&resultScalar, sizeof(resultScalar));
    memory_cleanse(&termScalar, sizeof(termScalar));
    
    return result;
}

void CDKGSession::ComputeVerificationVector()
{
    // vvec[i] = g * a_i (public key corresponding to each coefficient)
    myVvec.clear();
    myVvec.reserve(secretCoefficients.size());
    
    for (const auto& coeff : secretCoefficients) {
        myVvec.push_back(coeff.GetPublicKey());
    }
    
    LogPrint(BCLog::LLMQ, "CDKGSession::ComputeVerificationVector -- computed %zu vvec elements\n", myVvec.size());
}

std::vector<uint8_t> CDKGSession::EncryptShare(const CBLSSecretKey& share,
                                                const CBLSPublicKey& targetPubKey,
                                                size_t targetMemberIndex) const
{
    // =====================================================================
    // SECURITY: Use proper ECDH for key derivation
    //
    // This is the critical security fix. We now use our OPERATOR SECRET KEY
    // to compute a proper ECDH shared secret with the target's public key.
    // Only we and the target can derive this shared secret.
    //
    // Previous (INSECURE) approach: Derived key from public keys only
    // New (SECURE) approach: ECDH with sk_ours * pk_theirs
    // =====================================================================
    
    if (!myOperatorSecretKey || !myOperatorSecretKey->IsValid()) {
        LogPrintf("CDKGSession::EncryptShare -- CRITICAL: operator secret key not set! "
                  "Cannot perform secure ECDH. Call SetOperatorKey() first.\n");
        return {};
    }
    
    if (!targetPubKey.IsValid()) {
        LogPrintf("CDKGSession::EncryptShare -- invalid target public key\n");
        return {};
    }
    
    // Derive encryption key using ECDH with our secret key and their public key
    uint256 encKey = DeriveShareEncryptionKeyECDH(
        *myOperatorSecretKey,
        targetPubKey,
        quorumHash,
        static_cast<size_t>(myMemberIndex),
        targetMemberIndex
    );
    
    if (encKey.IsNull()) {
        LogPrintf("CDKGSession::EncryptShare -- ECDH key derivation failed\n");
        return {};
    }
    
    // Build context data for authentication (binds ciphertext to this specific share)
    CHashWriter contextHw(SER_GETHASH, 0);
    contextHw << std::string("DKG_SHARE_CONTEXT_V3");
    contextHw << quorumHash;
    contextHw << static_cast<uint64_t>(myMemberIndex);
    contextHw << static_cast<uint64_t>(targetMemberIndex);
    uint256 contextHash = contextHw.GetHash();
    std::vector<uint8_t> contextData(contextHash.begin(), contextHash.end());
    
    // Encrypt using AEAD
    std::vector<uint8_t> shareBytes = share.ToBytes();
    std::vector<uint8_t> ciphertext = AEADEncrypt(shareBytes, encKey, contextData);
    
    // Clear sensitive data
    memory_cleanse(shareBytes.data(), shareBytes.size());
    
    LogPrint(BCLog::LLMQ, "CDKGSession::EncryptShare -- encrypted share for member %zu using secure ECDH\n", 
             targetMemberIndex);
    
    return ciphertext;
}

bool CDKGSession::DecryptShare(const std::vector<uint8_t>& encrypted,
                                size_t senderMemberIndex,
                                CBLSSecretKey& shareOut) const
{
    // =====================================================================
    // SECURITY: Use proper ECDH for key derivation
    //
    // We use OUR secret key and the SENDER'S public key to derive the
    // same shared secret that the sender used (with their secret key and
    // our public key). This is the essence of Diffie-Hellman key exchange.
    //
    // Sender computed: sk_sender * pk_ours = sk_sender * sk_ours * G1
    // We compute: sk_ours * pk_sender = sk_ours * sk_sender * G1
    // Both are equal due to commutativity of scalar multiplication.
    // =====================================================================
    
    if (myMemberIndex < 0) {
        LogPrintf("CDKGSession::DecryptShare -- we are not a quorum member\n");
        return false;
    }
    
    if (!myOperatorSecretKey || !myOperatorSecretKey->IsValid()) {
        LogPrintf("CDKGSession::DecryptShare -- CRITICAL: operator secret key not set! "
                  "Cannot perform secure ECDH. Call SetOperatorKey() first.\n");
        return false;
    }
    
    // Get sender's public key
    if (senderMemberIndex >= members.size()) {
        LogPrintf("CDKGSession::DecryptShare -- invalid sender index\n");
        return false;
    }
    
    CBLSPublicKey senderPubKey;
    senderPubKey.SetBytes(members[senderMemberIndex]->state.vchOperatorPubKey);
    
    if (!senderPubKey.IsValid()) {
        LogPrintf("CDKGSession::DecryptShare -- invalid sender public key\n");
        return false;
    }
    
    // Derive decryption key using ECDH with our secret key and sender's public key
    // This produces the same key the sender derived (ECDH is symmetric)
    uint256 decKey = DeriveShareEncryptionKeyECDH(
        *myOperatorSecretKey,
        senderPubKey,
        quorumHash,
        senderMemberIndex,
        static_cast<size_t>(myMemberIndex)
    );
    
    if (decKey.IsNull()) {
        LogPrintf("CDKGSession::DecryptShare -- ECDH key derivation failed\n");
        return false;
    }
    
    // Build context data for authentication (must match encryption context)
    CHashWriter contextHw(SER_GETHASH, 0);
    contextHw << std::string("DKG_SHARE_CONTEXT_V3");
    contextHw << quorumHash;
    contextHw << static_cast<uint64_t>(senderMemberIndex);
    contextHw << static_cast<uint64_t>(myMemberIndex);
    uint256 contextHash = contextHw.GetHash();
    std::vector<uint8_t> contextData(contextHash.begin(), contextHash.end());
    
    // Decrypt using AEAD
    std::vector<uint8_t> decrypted;
    if (!AEADDecrypt(encrypted, decKey, decrypted, contextData)) {
        LogPrintf("CDKGSession::DecryptShare -- AEAD decryption failed (authentication or wrong key)\n");
        return false;
    }
    
    if (decrypted.size() != 32) {
        LogPrintf("CDKGSession::DecryptShare -- invalid decrypted size: %zu\n", decrypted.size());
        memory_cleanse(decrypted.data(), decrypted.size());
        return false;
    }
    
    bool success = shareOut.SetSecretKey(decrypted);
    memory_cleanse(decrypted.data(), decrypted.size());
    
    LogPrint(BCLog::LLMQ, "CDKGSession::DecryptShare -- decrypted share from member %zu using secure ECDH\n",
             senderMemberIndex);
    
    return success;
}

bool CDKGSession::VerifyShare(const CBLSSecretKey& share,
                               const std::vector<CBLSPublicKey>& vvec,
                               size_t memberIndex)
{
    // Verify that share is correct:
    // g * share == vvec[0] * vvec[1]^x * vvec[2]^(x^2) * ... * vvec[t-1]^(x^{t-1})
    // where x = memberIndex + 1
    
    if (vvec.empty() || !share.IsValid()) {
        return false;
    }
    
    // Compute left side: g * share
    CBLSPublicKey sharePk = share.GetPublicKey();
    
    // Compute right side: product of vvec[i]^(x^i)
    // This is the commitment evaluated at x
    
    size_t x = memberIndex + 1;  // 1-indexed
    
    // Start with vvec[0]
    blst_p1 result;
    blst_p1_affine vvec0_affine;
    blst_p1_uncompress(&vvec0_affine, vvec[0].begin());
    blst_p1_from_affine(&result, &vvec0_affine);
    
    size_t xPow = x;  // x^1
    
    for (size_t i = 1; i < vvec.size(); i++) {
        // Compute vvec[i]^(x^i)
        blst_p1_affine vi_affine;
        blst_p1 vi_point, vi_scaled;
        
        blst_p1_uncompress(&vi_affine, vvec[i].begin());
        blst_p1_from_affine(&vi_point, &vi_affine);
        
        // Scale by x^i
        uint8_t scalar[32] = {0};
        // Convert xPow to big-endian
        for (int j = 0; j < 8 && xPow > 0; j++) {
            scalar[31 - j] = static_cast<uint8_t>(xPow & 0xFF);
            xPow >>= 8;
        }
        xPow = x;
        for (size_t j = 0; j < i; j++) {
            xPow *= x;
        }
        
        // Reset scalar for current power
        memset(scalar, 0, 32);
        size_t currentPow = 1;
        for (size_t j = 0; j < i; j++) {
            currentPow *= x;
        }
        for (int j = 0; j < 8 && currentPow > 0; j++) {
            scalar[31 - j] = static_cast<uint8_t>(currentPow & 0xFF);
            currentPow >>= 8;
        }
        
        blst_p1_mult(&vi_scaled, &vi_point, scalar, 256);
        
        // Add to result
        blst_p1_add(&result, &result, &vi_scaled);
    }
    
    // Compress result and compare with share public key
    uint8_t resultBytes[48];
    blst_p1_compress(resultBytes, &result);
    
    CBLSPublicKey computedPk;
    computedPk.SetBytes(resultBytes, 48);
    
    return sharePk == computedPk;
}

CDKGContribution CDKGSession::CreateContribution()
{
    LOCK(cs);
    
    CDKGContribution contribution;
    
    // =====================================================================
    // SECURITY: Require operator secret key for DKG participation
    //
    // The operator secret key is REQUIRED for:
    // 1. ECDH-based share encryption (only recipient can decrypt)
    // 2. Signing contributions (proves authenticity)
    //
    // Without the operator key, we cannot securely participate in DKG.
    // This is a fundamental security requirement.
    // =====================================================================
    
    if (!myOperatorSecretKey || !myOperatorSecretKey->IsValid()) {
        LogPrintf("CDKGSession::CreateContribution -- CRITICAL ERROR: operator secret key not set!\n");
        LogPrintf("CDKGSession::CreateContribution -- Cannot participate in DKG without operator key.\n");
        LogPrintf("CDKGSession::CreateContribution -- Call SetOperatorKey() before CreateContribution().\n");
        
        // Return an invalid contribution rather than using insecure fallback
        contribution.quorumHash.SetNull();
        return contribution;
    }
    
    contribution.quorumHash = quorumHash;
    contribution.proTxHash = myProTxHash;
    contribution.memberIndex = static_cast<uint16_t>(myMemberIndex);
    
    // Generate secret polynomial
    GenerateSecretPolynomial();
    
    // Compute verification vector
    ComputeVerificationVector();
    contribution.vvec = myVvec;
    
    // Compute and encrypt shares for each member
    contribution.encryptedShares.resize(quorumSize);
    
    for (size_t i = 0; i < quorumSize; i++) {
        // Compute share s(i+1) for member i
        CBLSSecretKey share = EvaluatePolynomial(i);
        secretShares[i] = std::move(share);
        
        // Get member's operator public key
        CBLSPublicKey memberPk;
        memberPk.SetBytes(members[i]->state.vchOperatorPubKey);
        
        // Encrypt the share using secure ECDH
        contribution.encryptedShares[i] = EncryptShare(share, memberPk, i);
        
        if (contribution.encryptedShares[i].empty() && i != static_cast<size_t>(myMemberIndex)) {
            LogPrintf("CDKGSession::CreateContribution -- WARNING: failed to encrypt share for member %zu\n", i);
        }
    }
    
    // Sign the contribution with our operator secret key
    contribution.sig = myOperatorSecretKey->SignWithDomain(contribution.GetSignHash(), BLSDomainTags::QUORUM);
    
    if (!contribution.sig.IsValid()) {
        LogPrintf("CDKGSession::CreateContribution -- failed to sign contribution\n");
        contribution.quorumHash.SetNull();
        return contribution;
    }
    
    LogPrintf("CDKGSession::CreateContribution -- created contribution with %zu shares (secure ECDH)\n", quorumSize);
    
    return contribution;
}

bool CDKGSession::ProcessContribution(const CDKGContribution& contribution, CValidationState& state)
{
    LOCK(cs);
    
    if (contribution.quorumHash != quorumHash) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-quorum-hash");
    }
    
    auto it = membersMap.find(contribution.proTxHash);
    if (it == membersMap.end()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-not-member");
    }
    
    size_t memberIdx = it->second;
    if (contribution.memberIndex != memberIdx) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-member-index");
    }
    
    // Verify contribution structure
    if (contribution.vvec.size() != threshold) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-vvec-size");
    }
    
    if (contribution.encryptedShares.size() != quorumSize) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-shares-count");
    }
    
    // Verify signature
    CBLSPublicKey memberPk;
    if (!memberPk.SetBytes(members[memberIdx]->state.vchOperatorPubKey)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-operator-key");
    }
    
    if (!contribution.sig.VerifyWithDomain(memberPk, contribution.GetSignHash(), BLSDomainTags::QUORUM)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-sig");
    }
    
    // Store contribution
    receivedContributions[contribution.proTxHash] = contribution;
    receivedVvecs[memberIdx] = contribution.vvec;
    
    // If this is our share, decrypt and verify it
    if (myMemberIndex >= 0) {
        // TODO: Decrypt our share and verify against vvec
        // For now, mark as received
    }
    
    LogPrint(BCLog::LLMQ, "CDKGSession::ProcessContribution -- processed contribution from %s\n",
             contribution.proTxHash.ToString().substr(0, 16));
    
    return true;
}

CDKGComplaint CDKGSession::CreateComplaint()
{
    LOCK(cs);
    
    CDKGComplaint complaint;
    
    // Require operator key for signing
    if (!myOperatorSecretKey || !myOperatorSecretKey->IsValid()) {
        LogPrintf("CDKGSession::CreateComplaint -- operator key not set, cannot sign\n");
        complaint.quorumHash.SetNull();
        return complaint;
    }
    
    complaint.quorumHash = quorumHash;
    complaint.proTxHash = myProTxHash;
    complaint.memberIndex = static_cast<uint16_t>(myMemberIndex);
    complaint.badMembers.resize(quorumSize, false);
    
    // Check each member's contribution
    for (size_t i = 0; i < quorumSize; i++) {
        if (i == static_cast<size_t>(myMemberIndex)) continue;
        
        auto it = receivedContributions.find(members[i]->proTxHash);
        if (it == receivedContributions.end()) {
            // No contribution received - mark as bad
            complaint.badMembers[i] = true;
            complainedMembers.insert(i);
            LogPrint(BCLog::LLMQ, "CDKGSession::CreateComplaint -- no contribution from member %zu\n", i);
            continue;
        }
        
        // Decrypt and verify our share from this member
        const CDKGContribution& contrib = it->second;
        if (i < contrib.encryptedShares.size()) {
            CBLSSecretKey decryptedShare;
            if (!DecryptShare(contrib.encryptedShares[myMemberIndex], i, decryptedShare)) {
                // Failed to decrypt - mark as bad
                complaint.badMembers[i] = true;
                complainedMembers.insert(i);
                LogPrint(BCLog::LLMQ, "CDKGSession::CreateComplaint -- failed to decrypt share from member %zu\n", i);
            } else {
                // Verify the share against the verification vector
                if (!VerifyShare(decryptedShare, receivedVvecs[i], static_cast<size_t>(myMemberIndex))) {
                    complaint.badMembers[i] = true;
                    complainedMembers.insert(i);
                    LogPrint(BCLog::LLMQ, "CDKGSession::CreateComplaint -- invalid share from member %zu\n", i);
                } else {
                    // Share is valid - store it
                    receivedShares[i] = std::move(decryptedShare);
                }
            }
        }
    }
    
    // Sign complaint with our operator key
    complaint.sig = myOperatorSecretKey->SignWithDomain(complaint.GetSignHash(), BLSDomainTags::QUORUM);
    
    return complaint;
}

bool CDKGSession::ProcessComplaint(const CDKGComplaint& complaint, CValidationState& state)
{
    LOCK(cs);
    
    if (complaint.quorumHash != quorumHash) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-quorum-hash");
    }
    
    auto it = membersMap.find(complaint.proTxHash);
    if (it == membersMap.end()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-not-member");
    }
    
    size_t memberIdx = it->second;
    
    // Verify signature with domain separation
    CBLSPublicKey memberPk;
    if (!memberPk.SetBytes(members[memberIdx]->state.vchOperatorPubKey)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-operator-key");
    }
    
    if (!complaint.sig.VerifyWithDomain(memberPk, complaint.GetSignHash(), BLSDomainTags::QUORUM)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-sig");
    }
    
    // Store complaint
    receivedComplaints[complaint.proTxHash] = complaint;
    
    LogPrint(BCLog::LLMQ, "CDKGSession::ProcessComplaint -- processed complaint from %s\n",
             complaint.proTxHash.ToString().substr(0, 16));
    
    return true;
}

CDKGJustification CDKGSession::CreateJustification()
{
    LOCK(cs);
    
    CDKGJustification justification;
    
    // Require operator key for signing
    if (!myOperatorSecretKey || !myOperatorSecretKey->IsValid()) {
        LogPrintf("CDKGSession::CreateJustification -- operator key not set, cannot sign\n");
        justification.quorumHash.SetNull();
        return justification;
    }
    
    justification.quorumHash = quorumHash;
    justification.proTxHash = myProTxHash;
    justification.memberIndex = static_cast<uint16_t>(myMemberIndex);
    
    // Check which members complained about us
    for (const auto& [complainerHash, complaint] : receivedComplaints) {
        auto it = membersMap.find(complainerHash);
        if (it == membersMap.end()) continue;
        
        size_t complainerIdx = it->second;
        
        if (complaint.badMembers.size() > static_cast<size_t>(myMemberIndex) &&
            complaint.badMembers[myMemberIndex]) {
            // This member complained about us - reveal our share to them
            // This proves our share was valid if it matches our verification vector
            if (secretShares.count(complainerIdx)) {
                justification.contributions[static_cast<uint16_t>(complainerIdx)] = 
                    secretShares[complainerIdx].ToBytes();
                LogPrint(BCLog::LLMQ, "CDKGSession::CreateJustification -- revealing share for complainer %zu\n",
                         complainerIdx);
            }
        }
    }
    
    // Sign justification with our operator key
    justification.sig = myOperatorSecretKey->SignWithDomain(justification.GetSignHash(), BLSDomainTags::QUORUM);
    
    return justification;
}

bool CDKGSession::ProcessJustification(const CDKGJustification& justification, CValidationState& state)
{
    LOCK(cs);
    
    if (justification.quorumHash != quorumHash) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-quorum-hash");
    }
    
    auto it = membersMap.find(justification.proTxHash);
    if (it == membersMap.end()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-not-member");
    }
    
    size_t memberIdx = it->second;
    
    // Verify signature with domain separation
    CBLSPublicKey memberPk;
    if (!memberPk.SetBytes(members[memberIdx]->state.vchOperatorPubKey)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-operator-key");
    }
    
    if (!justification.sig.VerifyWithDomain(memberPk, justification.GetSignHash(), BLSDomainTags::QUORUM)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-sig");
    }
    
    // Process revealed shares
    auto vvecIt = receivedVvecs.find(memberIdx);
    if (vvecIt != receivedVvecs.end()) {
        for (const auto& [complainerIdx, shareBytes] : justification.contributions) {
            CBLSSecretKey share;
            if (share.SetSecretKey(shareBytes)) {
                // Verify the share against the vvec
                if (VerifyShare(share, vvecIt->second, complainerIdx)) {
                    // Share is valid - the complaint was false
                    LogPrint(BCLog::LLMQ, "CDKGSession::ProcessJustification -- share verified for member %d\n", complainerIdx);
                } else {
                    // Share is invalid - member is bad
                    badMembers.insert(memberIdx);
                    validMembers.erase(memberIdx);
                    LogPrint(BCLog::LLMQ, "CDKGSession::ProcessJustification -- invalid share, member %zu is bad\n", memberIdx);
                }
            }
        }
    }
    
    receivedJustifications[justification.proTxHash] = justification;
    
    return true;
}

void CDKGSession::AggregateVerificationVectors()
{
    LOCK(cs);
    
    quorumVvec.clear();
    quorumVvec.resize(threshold);
    
    // Initialize with identity
    for (size_t i = 0; i < threshold; i++) {
        quorumVvec[i] = CBLSPublicKey();
    }
    
    // Aggregate vvecs from valid members
    for (size_t memberIdx : validMembers) {
        auto it = receivedVvecs.find(memberIdx);
        if (it == receivedVvecs.end()) continue;
        
        const auto& vvec = it->second;
        if (vvec.size() != threshold) continue;
        
        std::vector<CBLSPublicKey> toAggregate;
        for (size_t i = 0; i < threshold; i++) {
            if (quorumVvec[i].IsValid()) {
                toAggregate = {quorumVvec[i], vvec[i]};
                quorumVvec[i] = CBLSPublicKey::AggregatePublicKeys(toAggregate);
            } else {
                quorumVvec[i] = vvec[i];
            }
        }
    }
    
    LogPrint(BCLog::LLMQ, "CDKGSession::AggregateVerificationVectors -- aggregated %zu vvecs\n", validMembers.size());
}

void CDKGSession::ComputeFinalSecretKeyShare()
{
    LOCK(cs);
    
    // Sum all valid shares we received
    // Collect references to valid shares (avoid copying secret keys)
    std::vector<const CBLSSecretKey*> sharesToAggregate;
    
    for (size_t memberIdx : validMembers) {
        auto it = receivedShares.find(memberIdx);
        if (it != receivedShares.end() && it->second.IsValid()) {
            sharesToAggregate.push_back(&(it->second));
        }
    }
    
    // Also add our own share to ourselves
    if (myMemberIndex >= 0 && secretShares.count(static_cast<size_t>(myMemberIndex))) {
        auto it = secretShares.find(static_cast<size_t>(myMemberIndex));
        if (it != secretShares.end()) {
            sharesToAggregate.push_back(&(it->second));
        }
    }
    
    if (sharesToAggregate.empty()) {
        LogPrintf("CDKGSession::ComputeFinalSecretKeyShare -- no valid shares\n");
        return;
    }
    
    // Sum shares using BLST
    blst_scalar sum;
    memset(&sum, 0, sizeof(sum));
    
    for (const CBLSSecretKey* share : sharesToAggregate) {
        blst_scalar shareScalar;
        std::vector<uint8_t> shareBytes = share->ToBytes();
        blst_scalar_from_bendian(&shareScalar, shareBytes.data());
        blst_sk_add_n_check(&sum, &sum, &shareScalar);
    }
    
    // Convert to secret key
    std::vector<uint8_t> sumBytes(32);
    blst_bendian_from_scalar(sumBytes.data(), &sum);
    secretKeyShare.SetSecretKey(sumBytes);
    
    memory_cleanse(&sum, sizeof(sum));
    
    LogPrint(BCLog::LLMQ, "CDKGSession::ComputeFinalSecretKeyShare -- computed from %zu shares\n", sharesToAggregate.size());
}

void CDKGSession::ComputeQuorumPublicKey()
{
    LOCK(cs);
    
    // Quorum public key is the first element of the aggregated vvec
    if (!quorumVvec.empty() && quorumVvec[0].IsValid()) {
        quorumPublicKey = quorumVvec[0];
        LogPrint(BCLog::LLMQ, "CDKGSession::ComputeQuorumPublicKey -- pk=%s\n", 
                  quorumPublicKey.ToString().substr(0, 32));
    }
}

CDKGPrematureCommitment CDKGSession::CreatePrematureCommitment()
{
    LOCK(cs);
    
    CDKGPrematureCommitment commitment;
    
    // Require operator key for signing
    if (!myOperatorSecretKey || !myOperatorSecretKey->IsValid()) {
        LogPrintf("CDKGSession::CreatePrematureCommitment -- operator key not set, cannot sign\n");
        commitment.quorumHash.SetNull();
        return commitment;
    }
    
    // Aggregate vvecs and compute results
    AggregateVerificationVectors();
    ComputeFinalSecretKeyShare();
    ComputeQuorumPublicKey();
    
    commitment.quorumHash = quorumHash;
    commitment.proTxHash = myProTxHash;
    commitment.memberIndex = static_cast<uint16_t>(myMemberIndex);
    
    // Mark valid members
    commitment.validMembers.resize(quorumSize, false);
    for (size_t idx : validMembers) {
        if (idx < quorumSize) {
            commitment.validMembers[idx] = true;
        }
    }
    
    commitment.quorumPublicKey = quorumPublicKey;
    
    // Hash of our secret key share (commitment without revealing the share)
    if (secretKeyShare.IsValid()) {
        std::vector<uint8_t> shareBytes = secretKeyShare.ToBytes();
        commitment.secretKeyShareHash = Hash(shareBytes.begin(), shareBytes.end());
        memory_cleanse(shareBytes.data(), shareBytes.size());
    }
    
    // Sign with our operator key
    commitment.sig = myOperatorSecretKey->SignWithDomain(commitment.GetSignHash(), BLSDomainTags::QUORUM);
    
    return commitment;
}

bool CDKGSession::ProcessPrematureCommitment(const CDKGPrematureCommitment& commitment, CValidationState& state)
{
    LOCK(cs);
    
    if (commitment.quorumHash != quorumHash) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-quorum-hash");
    }
    
    auto it = membersMap.find(commitment.proTxHash);
    if (it == membersMap.end()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-not-member");
    }
    
    receivedPrematureCommitments[commitment.proTxHash] = commitment;
    
    return true;
}

CDKGFinalCommitment CDKGSession::CreateFinalCommitment()
{
    LOCK(cs);
    
    CDKGFinalCommitment commitment;
    commitment.quorumHash = quorumHash;
    
    // Aggregate premature commitments
    // Find the most common quorum public key
    std::map<uint256, size_t> pkVotes;
    
    for (const auto& [proTxHash, premature] : receivedPrematureCommitments) {
        uint256 pkHash = premature.quorumPublicKey.GetHash();
        pkVotes[pkHash]++;
    }
    
    // Find the winning public key
    uint256 winningPkHash;
    size_t maxVotes = 0;
    for (const auto& [pkHash, votes] : pkVotes) {
        if (votes > maxVotes) {
            maxVotes = votes;
            winningPkHash = pkHash;
        }
    }
    
    // Collect signers who agreed on the winning public key
    commitment.signers.resize(quorumSize, false);
    commitment.validMembers.resize(quorumSize, false);
    std::vector<CBLSSignature> sigs;
    
    for (const auto& [proTxHash, premature] : receivedPrematureCommitments) {
        if (premature.quorumPublicKey.GetHash() == winningPkHash) {
            auto it = membersMap.find(proTxHash);
            if (it != membersMap.end()) {
                commitment.signers[it->second] = true;
                sigs.push_back(premature.sig);
                
                // Copy valid members if this is the first match
                if (!commitment.quorumPublicKey.IsValid()) {
                    commitment.quorumPublicKey = premature.quorumPublicKey;
                    for (size_t i = 0; i < premature.validMembers.size() && i < quorumSize; i++) {
                        commitment.validMembers[i] = premature.validMembers[i];
                    }
                }
            }
        }
    }
    
    commitment.quorumVvec = quorumVvec;
    
    // Aggregate signatures
    if (!sigs.empty()) {
        commitment.membersSig = CBLSSignature::AggregateSignatures(sigs);
    }
    
    LogPrintf("CDKGSession::CreateFinalCommitment -- %s\n", commitment.ToString());
    
    return commitment;
}

bool CDKGSession::ProcessFinalCommitment(const CDKGFinalCommitment& commitment, CValidationState& state)
{
    LOCK(cs);
    
    if (commitment.quorumHash != quorumHash) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-quorum-hash");
    }
    
    if (!commitment.Verify(members, true, llmqType, quorumHeight)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-dkg-final-commitment");
    }
    
    // Accept the final commitment
    quorumPublicKey = commitment.quorumPublicKey;
    quorumVvec = commitment.quorumVvec;
    phase = DKGPhase::FINALIZATION;
    
    LogPrintf("CDKGSession::ProcessFinalCommitment -- DKG complete: %s\n", commitment.ToString());
    
    return true;
}

bool CDKGSession::GetSecretKeyShare(CBLSSecretKey& skShareOut) const
{
    LOCK(cs);
    
    if (!secretKeyShare.IsValid()) {
        return false;
    }
    
    // Note: This creates a copy - caller is responsible for secure handling
    skShareOut.SetSecretKey(secretKeyShare.ToBytes());
    return true;
}

bool CDKGSession::GetQuorumPublicKey(CBLSPublicKey& pkOut) const
{
    LOCK(cs);
    
    if (!quorumPublicKey.IsValid()) {
        return false;
    }
    
    pkOut = quorumPublicKey;
    return true;
}

std::string CDKGSession::ToString() const
{
    LOCK(cs);
    
    std::ostringstream ss;
    ss << "CDKGSession("
       << "quorum=" << quorumHash.ToString().substr(0, 16)
       << ", height=" << quorumHeight
       << ", phase=" << DKGPhaseToString(phase)
       << ", members=" << quorumSize
       << ", threshold=" << threshold
       << ", valid=" << validMembers.size()
       << ", contributions=" << receivedContributions.size()
       << ")";
    return ss.str();
}

// ============================================================================
// CDKGSessionManager Implementation
// ============================================================================

CDKGSessionManager::CDKGSessionManager(CQuorumManager& _quorumManager)
    : quorumManager(_quorumManager)
{
}

void CDKGSessionManager::SetMyProTxHash(const uint256& _proTxHash)
{
    LOCK(cs);
    myProTxHash = _proTxHash;
}

bool CDKGSessionManager::SetMyOperatorKey(const CBLSSecretKey& operatorKey)
{
    LOCK(cs);
    
    if (!operatorKey.IsValid()) {
        LogPrintf("CDKGSessionManager::SetMyOperatorKey -- invalid operator key\n");
        return false;
    }
    
    // Store a copy of the key
    myOperatorKey = std::make_unique<CBLSSecretKey>();
    if (!myOperatorKey->SetSecretKey(operatorKey.ToBytes())) {
        myOperatorKey.reset();
        LogPrintf("CDKGSessionManager::SetMyOperatorKey -- failed to store operator key\n");
        return false;
    }
    
    LogPrintf("CDKGSessionManager::SetMyOperatorKey -- operator key configured successfully\n");
    return true;
}

bool CDKGSessionManager::HasOperatorKey() const
{
    LOCK(cs);
    return myOperatorKey && myOperatorKey->IsValid();
}

bool CDKGSessionManager::StartSession(LLMQType llmqType, const CBlockIndex* pindex)
{
    LOCK(cs);
    
    if (!pindex) return false;
    
    const auto& params = GetLLMQParams(llmqType);
    if (params.type == LLMQType::LLMQ_NONE) return false;
    
    // Calculate quorum hash
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << std::string("LLMQ_DKG");
    hw << static_cast<uint8_t>(llmqType);
    hw << pindex->GetBlockHash();
    uint256 quorumHash = hw.GetHash();
    
    // Check if session already exists
    if (activeSessions.count(quorumHash)) {
        return false;
    }
    
    // Select members using the same deterministic algorithm as BuildQuorum.
    // Before nConsensusFixHeight, use the legacy Hash(quorumHash, proTxHash) sort
    // for backward compatibility with existing quorum sessions.
    // After nConsensusFixHeight, use SelectQuorumMembers which matches BuildQuorum.
    const auto& cp = GetParams().GetConsensus();
    std::vector<CDeterministicMNCPtr> members;
    
    if (pindex->nHeight >= cp.nConsensusFixHeight) {
        members = quorumManager.SelectQuorumMembers(llmqType, pindex);
    } else {
        auto mnList = deterministicMNManager->GetListForBlock(pindex);
        if (!mnList) return false;
        
        mnList->ForEachMN(true, [&](const CDeterministicMNCPtr& mn) {
            members.push_back(mn);
        });
        
        std::sort(members.begin(), members.end(), [&](const auto& a, const auto& b) {
            CHashWriter hw1(SER_GETHASH, 0);
            hw1 << quorumHash << a->proTxHash;
            CHashWriter hw2(SER_GETHASH, 0);
            hw2 << quorumHash << b->proTxHash;
            return hw1.GetHash() < hw2.GetHash();
        });
        
        if (members.size() > static_cast<size_t>(params.size)) {
            members.resize(params.size);
        }
    }
    
    if (members.size() < static_cast<size_t>(params.minSize)) {
        LogPrintf("CDKGSessionManager::StartSession -- not enough members: %zu < %d\n",
                  members.size(), params.minSize);
        return false;
    }
    
    // Create session
    auto session = std::make_shared<CDKGSession>();
    if (!session->Init(quorumHash, pindex->nHeight, llmqType, members, myProTxHash)) {
        return false;
    }
    
    // Set the operator key if we're a member and have the key
    if (session->IsOurTurn() && myOperatorKey && myOperatorKey->IsValid()) {
        if (!session->SetOperatorKey(*myOperatorKey)) {
            LogPrintf("CDKGSessionManager::StartSession -- WARNING: failed to set operator key for session\n");
        }
    }
    
    activeSessions[quorumHash] = session;
    
    LogPrintf("CDKGSessionManager::StartSession -- started DKG for quorum %s at height %d, isMember=%d\n",
              quorumHash.ToString().substr(0, 16), pindex->nHeight, session->IsOurTurn() ? 1 : 0);
    
    return true;
}

bool CDKGSessionManager::IsRateLimited(const uint256& proTxHash)
{
    // Must be called with cs lock held
    int64_t now = GetTime();
    
    auto it = rateLimitMap.find(proTxHash);
    if (it == rateLimitMap.end()) {
        // First message from this member
        rateLimitMap[proTxHash] = {now, 1};
        return false;
    }
    
    RateLimitEntry& entry = it->second;
    
    // Check if we're in a new time window
    if (now - entry.windowStart >= RATE_LIMIT_WINDOW) {
        // Reset the window
        entry.windowStart = now;
        entry.messageCount = 1;
        return false;
    }
    
    // Still in the same window - check count
    if (entry.messageCount >= MAX_MESSAGES_PER_WINDOW) {
        LogPrintf("CDKGSessionManager::IsRateLimited -- member %s rate limited (%d messages in %ld seconds)\n",
                  proTxHash.ToString().substr(0, 16), entry.messageCount, now - entry.windowStart);
        return true;
    }
    
    // Increment count
    entry.messageCount++;
    return false;
}

bool CDKGSessionManager::ProcessContribution(const CDKGContribution& contribution, CValidationState& state)
{
    LOCK(cs);
    
    // Rate limiting to prevent DoS
    if (IsRateLimited(contribution.proTxHash)) {
        return state.DoS(10, false, REJECT_INVALID, "dkg-rate-limited");
    }
    
    auto it = activeSessions.find(contribution.quorumHash);
    if (it == activeSessions.end()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-dkg-no-session");
    }
    
    return it->second->ProcessContribution(contribution, state);
}

bool CDKGSessionManager::ProcessComplaint(const CDKGComplaint& complaint, CValidationState& state)
{
    LOCK(cs);
    
    // Rate limiting to prevent DoS
    if (IsRateLimited(complaint.proTxHash)) {
        return state.DoS(10, false, REJECT_INVALID, "dkg-rate-limited");
    }
    
    auto it = activeSessions.find(complaint.quorumHash);
    if (it == activeSessions.end()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-dkg-no-session");
    }
    
    return it->second->ProcessComplaint(complaint, state);
}

bool CDKGSessionManager::ProcessJustification(const CDKGJustification& justification, CValidationState& state)
{
    LOCK(cs);
    
    // Rate limiting to prevent DoS
    if (IsRateLimited(justification.proTxHash)) {
        return state.DoS(10, false, REJECT_INVALID, "dkg-rate-limited");
    }
    
    auto it = activeSessions.find(justification.quorumHash);
    if (it == activeSessions.end()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-dkg-no-session");
    }
    
    return it->second->ProcessJustification(justification, state);
}

bool CDKGSessionManager::ProcessPrematureCommitment(const CDKGPrematureCommitment& commitment, CValidationState& state)
{
    LOCK(cs);
    
    // Rate limiting to prevent DoS
    if (IsRateLimited(commitment.proTxHash)) {
        return state.DoS(10, false, REJECT_INVALID, "dkg-rate-limited");
    }
    
    auto it = activeSessions.find(commitment.quorumHash);
    if (it == activeSessions.end()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-dkg-no-session");
    }
    
    return it->second->ProcessPrematureCommitment(commitment, state);
}

bool CDKGSessionManager::ProcessFinalCommitment(const CDKGFinalCommitment& commitment, CValidationState& state)
{
    LOCK(cs);
    
    // Store final commitment
    finalCommitments[commitment.quorumHash] = commitment;
    
    // If we have an active session, process it there too
    auto it = activeSessions.find(commitment.quorumHash);
    if (it != activeSessions.end()) {
        return it->second->ProcessFinalCommitment(commitment, state);
    }
    
    return true;
}

std::shared_ptr<CDKGSession> CDKGSessionManager::GetSession(const uint256& quorumHash) const
{
    LOCK(cs);
    
    auto it = activeSessions.find(quorumHash);
    if (it != activeSessions.end()) {
        return it->second;
    }
    return nullptr;
}

bool CDKGSessionManager::GetFinalCommitment(const uint256& quorumHash, CDKGFinalCommitment& commitmentOut) const
{
    LOCK(cs);
    
    auto it = finalCommitments.find(quorumHash);
    if (it != finalCommitments.end()) {
        commitmentOut = it->second;
        return true;
    }
    return false;
}

bool CDKGSessionManager::GetSecretKeyShare(const uint256& quorumHash, CBLSSecretKey& skShareOut) const
{
    LOCK(cs);
    
    auto it = activeSessions.find(quorumHash);
    if (it != activeSessions.end()) {
        return it->second->GetSecretKeyShare(skShareOut);
    }
    return false;
}

bool CDKGSessionManager::IsDKGComplete(const uint256& quorumHash) const
{
    LOCK(cs);
    
    return finalCommitments.count(quorumHash) > 0;
}

void CDKGSessionManager::UpdatedBlockTip(const CBlockIndex* pindex)
{
    LOCK(cs);
    
    if (!pindex) return;
    
    // Advance phase for all active sessions
    for (auto& [quorumHash, session] : activeSessions) {
        session->AdvancePhase(pindex->nHeight);
    }
    
    // Check if we need to start new DKG sessions
    // Note: LLMQ_5_60 is for regtest/devnet testing with small node counts
    static const std::vector<LLMQType> llmqTypes = {
        LLMQType::LLMQ_5_60,
        LLMQType::LLMQ_50_60,
        LLMQType::LLMQ_400_60
    };
    
    for (LLMQType llmqType : llmqTypes) {
        const auto& params = GetLLMQParams(llmqType);
        if (params.type == LLMQType::LLMQ_NONE) continue;
        
        // Start DKG at interval boundaries
        if (pindex->nHeight % params.dkgInterval == 0) {
            StartSession(llmqType, pindex);
        }
    }
}

void CDKGSessionManager::Cleanup()
{
    LOCK(cs);
    
    // Remove completed sessions older than some threshold
    // Keep final commitments for longer
    auto it = activeSessions.begin();
    while (it != activeSessions.end()) {
        if (it->second->IsComplete()) {
            it = activeSessions.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// Global Initialization
// ============================================================================

void InitDKG(CQuorumManager& quorumManager)
{
    dkgSessionManager = std::make_unique<CDKGSessionManager>(quorumManager);
    LogPrintf("DKG subsystem initialized\n");
}

void StopDKG()
{
    dkgSessionManager.reset();
    LogPrintf("DKG subsystem stopped\n");
}

} // namespace llmq
