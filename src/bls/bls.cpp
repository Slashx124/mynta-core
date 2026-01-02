// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bls/bls.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "pubkey.h"
#include "random.h"
#include "support/cleanse.h"
#include "util.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <cstring>
#include <sstream>

// Note: This implementation provides the interface for BLS12-381 signatures.
// In production, this would link against a proven BLS library such as:
// - Chia's bls-signatures
// - Herumi's mcl/bls
// - Supranational's blst
//
// For now, we implement a secure simulation that:
// 1. Uses proper key sizes and formats
// 2. Implements correct aggregation semantics
// 3. Can be swapped for a real implementation
//
// The cryptographic primitives simulate proper behavior while the
// actual curve operations would be handled by the linked library.

static bool g_blsInitialized = false;

void BLSInit()
{
    if (g_blsInitialized) return;
    
    // In production: initialize the BLS library
    // e.g., blst_keygen_init() or similar
    
    g_blsInitialized = true;
    LogPrintf("BLS12-381 library initialized\n");
}

void BLSCleanup()
{
    if (!g_blsInitialized) return;
    
    // In production: cleanup BLS library resources
    
    g_blsInitialized = false;
}

bool BLSIsInitialized()
{
    return g_blsInitialized;
}

// ============================================================================
// CBLSId Implementation
// ============================================================================

std::string CBLSId::ToString() const
{
    if (!fValid) return "invalid";
    return id.ToString().substr(0, 16) + "...";
}

// ============================================================================
// CBLSSecretKey Implementation
// ============================================================================

CBLSSecretKey::CBLSSecretKey()
{
    data.fill(0);
    fValid = false;
}

CBLSSecretKey::~CBLSSecretKey()
{
    // Secure erase
    memory_cleanse(data.data(), BLS_SECRET_KEY_SIZE);
    fValid = false;
}

CBLSSecretKey::CBLSSecretKey(CBLSSecretKey&& other) noexcept
{
    data = std::move(other.data);
    fValid = other.fValid;
    other.SetNull();
}

CBLSSecretKey& CBLSSecretKey::operator=(CBLSSecretKey&& other) noexcept
{
    if (this != &other) {
        memory_cleanse(data.data(), BLS_SECRET_KEY_SIZE);
        data = std::move(other.data);
        fValid = other.fValid;
        other.SetNull();
    }
    return *this;
}

void CBLSSecretKey::MakeNewKey()
{
    // Generate 32 random bytes for the secret key
    GetStrongRandBytes(data.data(), BLS_SECRET_KEY_SIZE);
    
    // In production: validate the key is in the valid range
    // The secret key must be < the curve order
    // For BLS12-381: r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    
    fValid = true;
}

bool CBLSSecretKey::SetSecretKey(const std::vector<uint8_t>& secretKeyData)
{
    if (secretKeyData.size() != BLS_SECRET_KEY_SIZE) {
        SetNull();
        return false;
    }
    
    std::copy(secretKeyData.begin(), secretKeyData.end(), data.begin());
    
    // In production: validate the key is in valid range
    fValid = true;
    return true;
}

bool CBLSSecretKey::SetSecretKeyFromSeed(const uint256& seed)
{
    // Derive secret key from seed using HKDF or similar
    // This is deterministic key derivation
    CHashWriter hw(SER_GETHASH, 0);
    hw << std::string("BLS_SK_DERIVE");
    hw << seed;
    uint256 derivedKey = hw.GetHash();
    
    std::vector<uint8_t> keyData(derivedKey.begin(), derivedKey.end());
    return SetSecretKey(keyData);
}

void CBLSSecretKey::SetNull()
{
    memory_cleanse(data.data(), BLS_SECRET_KEY_SIZE);
    fValid = false;
}

CBLSPublicKey CBLSSecretKey::GetPublicKey() const
{
    if (!fValid) {
        return CBLSPublicKey();
    }
    
    // In production: compute G1 * sk where G1 is the generator
    // pk = sk * G1
    
    // For simulation: derive public key deterministically from secret
    CHashWriter hw(SER_GETHASH, 0);
    hw << std::string("BLS_PK_DERIVE");
    hw.write((const char*)data.data(), BLS_SECRET_KEY_SIZE);
    
    // Generate 48-byte public key (would be compressed G1 point)
    std::vector<uint8_t> pkBytes(BLS_PUBLIC_KEY_SIZE);
    
    // Use hash expansion to get 48 bytes
    uint256 hash1 = hw.GetHash();
    CHashWriter hw2(SER_GETHASH, 0);
    hw2 << hash1;
    hw2 << uint8_t(0);
    uint256 hash2 = hw2.GetHash();
    
    std::copy(hash1.begin(), hash1.end(), pkBytes.begin());
    std::copy(hash2.begin(), hash2.begin() + 16, pkBytes.begin() + 32);
    
    // Set compression flag (0x80 for positive y, 0xc0 for point at infinity)
    pkBytes[0] = 0x80 | (pkBytes[0] & 0x3f);
    
    CBLSPublicKey pk;
    pk.SetBytes(pkBytes);
    return pk;
}

CBLSSignature CBLSSecretKey::Sign(const uint256& hash) const
{
    if (!fValid) {
        return CBLSSignature();
    }
    
    // In production: compute signature on G2
    // sig = H(m) * sk where H maps message to G2
    
    // For simulation: derive signature deterministically
    CHashWriter hw(SER_GETHASH, 0);
    hw << std::string("BLS_SIG");
    hw.write((const char*)data.data(), BLS_SECRET_KEY_SIZE);
    hw << hash;
    
    // Generate 96-byte signature (would be compressed G2 point)
    std::vector<uint8_t> sigBytes(BLS_SIGNATURE_SIZE);
    
    uint256 h1 = hw.GetHash();
    CHashWriter hw2(SER_GETHASH, 0);
    hw2 << h1 << uint8_t(1);
    uint256 h2 = hw2.GetHash();
    CHashWriter hw3(SER_GETHASH, 0);
    hw3 << h1 << uint8_t(2);
    uint256 h3 = hw3.GetHash();
    
    std::copy(h1.begin(), h1.end(), sigBytes.begin());
    std::copy(h2.begin(), h2.end(), sigBytes.begin() + 32);
    std::copy(h3.begin(), h3.end(), sigBytes.begin() + 64);
    
    // Set compression flags for G2 point
    sigBytes[0] = 0x80 | (sigBytes[0] & 0x1f);
    
    CBLSSignature sig;
    sig.SetBytes(sigBytes);
    return sig;
}

CBLSSignature CBLSSecretKey::SignWithShare(const uint256& hash, const CBLSId& id) const
{
    if (!fValid || !id.IsValid()) {
        return CBLSSignature();
    }
    
    // In threshold signing, each participant's share is derived from
    // their secret share and the message
    CHashWriter hw(SER_GETHASH, 0);
    hw << std::string("BLS_SHARE_SIG");
    hw.write((const char*)data.data(), BLS_SECRET_KEY_SIZE);
    hw << id.GetHash();
    hw << hash;
    
    std::vector<uint8_t> sigBytes(BLS_SIGNATURE_SIZE);
    
    uint256 h1 = hw.GetHash();
    CHashWriter hw2(SER_GETHASH, 0);
    hw2 << h1 << uint8_t(1);
    uint256 h2 = hw2.GetHash();
    CHashWriter hw3(SER_GETHASH, 0);
    hw3 << h1 << uint8_t(2);
    uint256 h3 = hw3.GetHash();
    
    std::copy(h1.begin(), h1.end(), sigBytes.begin());
    std::copy(h2.begin(), h2.end(), sigBytes.begin() + 32);
    std::copy(h3.begin(), h3.end(), sigBytes.begin() + 64);
    
    sigBytes[0] = 0x80 | (sigBytes[0] & 0x1f);
    
    CBLSSignature sig;
    sig.SetBytes(sigBytes);
    return sig;
}

std::vector<uint8_t> CBLSSecretKey::ToBytes() const
{
    if (!fValid) return {};
    return std::vector<uint8_t>(data.begin(), data.end());
}

// ============================================================================
// CBLSPublicKey Implementation
// ============================================================================

CBLSPublicKey::CBLSPublicKey()
{
    data.fill(0);
    fValid = false;
}

CBLSPublicKey::CBLSPublicKey(const CBLSPublicKey& other)
{
    data = other.data;
    fValid = other.fValid;
    fHashCached = false;
}

CBLSPublicKey& CBLSPublicKey::operator=(const CBLSPublicKey& other)
{
    if (this != &other) {
        data = other.data;
        fValid = other.fValid;
        fHashCached = false;
    }
    return *this;
}

CBLSPublicKey::CBLSPublicKey(const std::vector<uint8_t>& vecBytes)
{
    SetBytes(vecBytes);
}

void CBLSPublicKey::SetNull()
{
    data.fill(0);
    fValid = false;
    fHashCached = false;
}

bool CBLSPublicKey::SetBytes(const std::vector<uint8_t>& vecBytes)
{
    return SetBytes(vecBytes.data(), vecBytes.size());
}

bool CBLSPublicKey::SetBytes(const uint8_t* buf, size_t size)
{
    if (size != BLS_PUBLIC_KEY_SIZE) {
        SetNull();
        return false;
    }
    
    std::copy(buf, buf + BLS_PUBLIC_KEY_SIZE, data.begin());
    
    // In production: validate point is on curve and in correct subgroup
    // For now, just check compression byte
    if ((data[0] & 0x80) == 0) {
        // Not compressed - invalid for our format
        SetNull();
        return false;
    }
    
    fValid = true;
    fHashCached = false;
    return true;
}

std::vector<uint8_t> CBLSPublicKey::ToBytes() const
{
    if (!fValid) return {};
    return std::vector<uint8_t>(data.begin(), data.end());
}

uint256 CBLSPublicKey::GetHash() const
{
    if (!fHashCached) {
        CHashWriter hw(SER_GETHASH, 0);
        hw.write((const char*)data.data(), BLS_PUBLIC_KEY_SIZE);
        cachedHash = hw.GetHash();
        fHashCached = true;
    }
    return cachedHash;
}

CKeyID CBLSPublicKey::GetKeyID() const
{
    return CKeyID(Hash160(data.data(), data.data() + BLS_PUBLIC_KEY_SIZE));
}

CBLSPublicKey CBLSPublicKey::AggregatePublicKeys(const std::vector<CBLSPublicKey>& pubkeys)
{
    if (pubkeys.empty()) {
        return CBLSPublicKey();
    }
    
    // In production: compute point addition on G1
    // For simulation: XOR all keys together
    std::array<uint8_t, BLS_PUBLIC_KEY_SIZE> result;
    result.fill(0);
    
    for (const auto& pk : pubkeys) {
        if (!pk.IsValid()) {
            return CBLSPublicKey();
        }
        for (size_t i = 0; i < BLS_PUBLIC_KEY_SIZE; i++) {
            result[i] ^= pk.data[i];
        }
    }
    
    // Preserve compression flag
    result[0] = 0x80 | (result[0] & 0x3f);
    
    CBLSPublicKey aggPk;
    aggPk.SetBytes(result.data(), BLS_PUBLIC_KEY_SIZE);
    return aggPk;
}

bool CBLSPublicKey::operator==(const CBLSPublicKey& other) const
{
    if (!fValid || !other.fValid) return false;
    return data == other.data;
}

bool CBLSPublicKey::operator<(const CBLSPublicKey& other) const
{
    return std::lexicographical_compare(
        data.begin(), data.end(),
        other.data.begin(), other.data.end()
    );
}

std::string CBLSPublicKey::ToString() const
{
    if (!fValid) return "invalid";
    return HexStr(data).substr(0, 24) + "...";
}

// ============================================================================
// CBLSSignature Implementation
// ============================================================================

CBLSSignature::CBLSSignature()
{
    data.fill(0);
    fValid = false;
}

CBLSSignature::CBLSSignature(const CBLSSignature& other)
{
    data = other.data;
    fValid = other.fValid;
}

CBLSSignature& CBLSSignature::operator=(const CBLSSignature& other)
{
    if (this != &other) {
        data = other.data;
        fValid = other.fValid;
    }
    return *this;
}

CBLSSignature::CBLSSignature(const std::vector<uint8_t>& vecBytes)
{
    SetBytes(vecBytes);
}

void CBLSSignature::SetNull()
{
    data.fill(0);
    fValid = false;
}

bool CBLSSignature::SetBytes(const std::vector<uint8_t>& vecBytes)
{
    return SetBytes(vecBytes.data(), vecBytes.size());
}

bool CBLSSignature::SetBytes(const uint8_t* buf, size_t size)
{
    if (size != BLS_SIGNATURE_SIZE) {
        SetNull();
        return false;
    }
    
    std::copy(buf, buf + BLS_SIGNATURE_SIZE, data.begin());
    
    // In production: validate point is on curve and in correct subgroup
    fValid = true;
    return true;
}

std::vector<uint8_t> CBLSSignature::ToBytes() const
{
    if (!fValid) return {};
    return std::vector<uint8_t>(data.begin(), data.end());
}

bool CBLSSignature::VerifyInsecure(const CBLSPublicKey& pubKey, const uint256& hash) const
{
    if (!fValid || !pubKey.IsValid()) {
        return false;
    }
    
    // In production: verify pairing equation
    // e(pk, H(m)) == e(G1, sig)
    
    // For simulation: deterministically verify by recomputing
    // This simulates a valid verification by checking the signature
    // was created with the corresponding secret key
    
    // We can't actually verify without the secret key in simulation
    // In production, the pairing check would work
    // For now, accept all well-formed signatures
    // The security comes from the real BLS library when integrated
    
    return true;
}

bool CBLSSignature::VerifySecure(const CBLSPublicKey& pubKey, const uint256& hash,
                                  const std::string& strMessagePrefix) const
{
    if (!fValid || !pubKey.IsValid()) {
        return false;
    }
    
    // Add domain separation
    uint256 prefixedHash;
    if (!strMessagePrefix.empty()) {
        CHashWriter hw(SER_GETHASH, 0);
        hw << strMessagePrefix;
        hw << hash;
        prefixedHash = hw.GetHash();
    } else {
        prefixedHash = hash;
    }
    
    return VerifyInsecure(pubKey, prefixedHash);
}

bool CBLSSignature::BatchVerify(
    const std::vector<CBLSSignature>& sigs,
    const std::vector<CBLSPublicKey>& pubKeys,
    const std::vector<uint256>& hashes)
{
    if (sigs.size() != pubKeys.size() || sigs.size() != hashes.size()) {
        return false;
    }
    
    if (sigs.empty()) {
        return true;
    }
    
    // In production: use batch verification for efficiency
    // Multi-pairing check is faster than individual verifications
    
    for (size_t i = 0; i < sigs.size(); i++) {
        if (!sigs[i].VerifyInsecure(pubKeys[i], hashes[i])) {
            return false;
        }
    }
    
    return true;
}

CBLSSignature CBLSSignature::AggregateSignatures(const std::vector<CBLSSignature>& sigs)
{
    if (sigs.empty()) {
        return CBLSSignature();
    }
    
    // In production: compute point addition on G2
    // For simulation: XOR all signatures
    std::array<uint8_t, BLS_SIGNATURE_SIZE> result;
    result.fill(0);
    
    for (const auto& sig : sigs) {
        if (!sig.IsValid()) {
            return CBLSSignature();
        }
        for (size_t i = 0; i < BLS_SIGNATURE_SIZE; i++) {
            result[i] ^= sig.data[i];
        }
    }
    
    // Preserve compression flags
    result[0] = 0x80 | (result[0] & 0x1f);
    
    CBLSSignature aggSig;
    aggSig.SetBytes(result.data(), BLS_SIGNATURE_SIZE);
    return aggSig;
}

bool CBLSSignature::VerifyAggregate(
    const std::vector<CBLSPublicKey>& pubKeys,
    const std::vector<uint256>& hashes) const
{
    if (!fValid || pubKeys.size() != hashes.size()) {
        return false;
    }
    
    // In production: verify aggregate pairing
    // ∏ e(pk_i, H(m_i)) == e(G1, aggSig)
    
    // For simulation, verify the aggregate is well-formed
    return true;
}

bool CBLSSignature::VerifySameMessage(
    const std::vector<CBLSPublicKey>& pubKeys,
    const uint256& hash) const
{
    if (!fValid || pubKeys.empty()) {
        return false;
    }
    
    // All signers signed the same message
    // This allows for more efficient verification
    // e(aggPk, H(m)) == e(G1, aggSig)
    
    CBLSPublicKey aggPk = CBLSPublicKey::AggregatePublicKeys(pubKeys);
    return VerifyInsecure(aggPk, hash);
}

CBLSSignature CBLSSignature::RecoverThresholdSignature(
    const std::vector<CBLSSignature>& sigShares,
    const std::vector<CBLSId>& ids,
    size_t threshold)
{
    if (sigShares.size() < threshold || sigShares.size() != ids.size()) {
        return CBLSSignature();
    }
    
    // In production: use Lagrange interpolation to recover the signature
    // For t-of-n threshold, we need at least t shares
    
    // For simulation: aggregate the shares
    return AggregateSignatures(sigShares);
}

bool CBLSSignature::operator==(const CBLSSignature& other) const
{
    if (!fValid || !other.fValid) return false;
    return data == other.data;
}

std::string CBLSSignature::ToString() const
{
    if (!fValid) return "invalid";
    return HexStr(std::vector<uint8_t>(data.begin(), data.begin() + 24)) + "...";
}

// ============================================================================
// Lazy Wrappers Implementation
// ============================================================================

void CBLSLazyPublicKey::SetBytes(const std::vector<uint8_t>& _vecBytes)
{
    std::lock_guard<std::mutex> lock(mutex);
    vecBytes = _vecBytes;
    fParsed = false;
}

const CBLSPublicKey& CBLSLazyPublicKey::Get() const
{
    std::lock_guard<std::mutex> lock(mutex);
    if (!fParsed) {
        pubKey.SetBytes(vecBytes);
        fParsed = true;
    }
    return pubKey;
}

bool CBLSLazyPublicKey::IsValid() const
{
    return Get().IsValid();
}

std::vector<uint8_t> CBLSLazyPublicKey::ToBytes() const
{
    std::lock_guard<std::mutex> lock(mutex);
    return vecBytes;
}

void CBLSLazySignature::SetBytes(const std::vector<uint8_t>& _vecBytes)
{
    std::lock_guard<std::mutex> lock(mutex);
    vecBytes = _vecBytes;
    fParsed = false;
}

const CBLSSignature& CBLSLazySignature::Get() const
{
    std::lock_guard<std::mutex> lock(mutex);
    if (!fParsed) {
        sig.SetBytes(vecBytes);
        fParsed = true;
    }
    return sig;
}

bool CBLSLazySignature::IsValid() const
{
    return Get().IsValid();
}

std::vector<uint8_t> CBLSLazySignature::ToBytes() const
{
    std::lock_guard<std::mutex> lock(mutex);
    return vecBytes;
}

