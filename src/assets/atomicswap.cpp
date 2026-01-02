// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assets/atomicswap.h"
#include "hash.h"
#include "random.h"
#include "script/script.h"
#include "script/standard.h"
#include "util.h"

#include <algorithm>
#include <sstream>

std::unique_ptr<CAtomicSwapOrderBook> atomicSwapOrderBook;

// ============================================================================
// CAtomicSwapOffer Implementation
// ============================================================================

double CAtomicSwapOffer::GetRate() const
{
    if (makerAmount == 0) return 0;
    return static_cast<double>(takerAmount) / static_cast<double>(makerAmount);
}

bool CAtomicSwapOffer::IsExpired(int currentHeight) const
{
    return currentHeight >= createdHeight + static_cast<int>(timeoutBlocks);
}

std::string CAtomicSwapOffer::ToString() const
{
    std::ostringstream ss;
    ss << "CAtomicSwapOffer("
       << "hash=" << offerHash.ToString().substr(0, 16)
       << ", maker=" << (makerAssetName.empty() ? "MYNTA" : makerAssetName)
       << ":" << makerAmount
       << ", taker=" << (takerAssetName.empty() ? "MYNTA" : takerAssetName)
       << ":" << takerAmount
       << ", rate=" << GetRate()
       << ", active=" << isActive
       << ")";
    return ss.str();
}

// ============================================================================
// CHTLC Implementation
// ============================================================================

CScript CHTLC::GetRedeemScript() const
{
    return HTLCScript::CreateHTLCScript(
        std::vector<unsigned char>(hashLock.begin(), hashLock.end()),
        receiverAddress,
        senderAddress,
        timeLock
    );
}

CScript CHTLC::GetP2SHScript() const
{
    CScript redeemScript = GetRedeemScript();
    return GetScriptForDestination(CScriptID(redeemScript));
}

bool CHTLC::VerifyPreimage(const std::vector<unsigned char>& testPreimage) const
{
    uint256 testHash;
    CSHA256().Write(testPreimage.data(), testPreimage.size()).Finalize(testHash.begin());
    return testHash == hashLock;
}

bool CHTLC::CanRefund(int currentHeight) const
{
    return currentHeight >= static_cast<int>(timeLock);
}

std::string CHTLC::ToString() const
{
    std::ostringstream ss;
    ss << "CHTLC("
       << "id=" << htlcId.ToString().substr(0, 16)
       << ", asset=" << (assetName.empty() ? "MYNTA" : assetName)
       << ", amount=" << amount
       << ", timeLock=" << timeLock
       << ", state=" << static_cast<int>(state)
       << ")";
    return ss.str();
}

// ============================================================================
// CAtomicSwap Implementation
// ============================================================================

std::string CAtomicSwap::ToString() const
{
    std::ostringstream ss;
    ss << "CAtomicSwap("
       << "id=" << swapId.ToString().substr(0, 16)
       << ", state=" << static_cast<int>(state)
       << ", makerHTLC=" << makerHtlc.ToString()
       << ", takerHTLC=" << takerHtlc.ToString()
       << ")";
    return ss.str();
}

// ============================================================================
// HTLCScript Namespace Implementation
// ============================================================================

namespace HTLCScript {

CScript CreateHTLCScript(
    const std::vector<unsigned char>& hashLock,
    const CScript& receiverScript,
    const CScript& senderScript,
    uint32_t timeoutBlocks)
{
    /**
     * HTLC Script Structure:
     * 
     * OP_IF
     *     # Claim path: receiver reveals preimage
     *     OP_SHA256 <hashLock> OP_EQUALVERIFY
     *     <receiver_pubkey_hash> OP_CHECKSIG
     * OP_ELSE
     *     # Refund path: sender reclaims after timeout
     *     <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
     *     <sender_pubkey_hash> OP_CHECKSIG
     * OP_ENDIF
     * 
     * To claim: <sig> <pubkey> <preimage> OP_TRUE
     * To refund: <sig> <pubkey> OP_FALSE
     */
    
    CScript script;
    
    script << OP_IF;
    
    // Claim path
    script << OP_SHA256;
    script << hashLock;
    script << OP_EQUALVERIFY;
    
    // Extract pubkey hash from receiver script if P2PKH
    txnouttype type;
    std::vector<std::vector<unsigned char>> solutions;
    if (Solver(receiverScript, type, solutions) && type == TX_PUBKEYHASH) {
        script << OP_DUP << OP_HASH160;
        script << solutions[0];
        script << OP_EQUALVERIFY << OP_CHECKSIG;
    } else {
        // Fallback: embed the script directly
        script << receiverScript;
    }
    
    script << OP_ELSE;
    
    // Refund path
    script << CScriptNum(timeoutBlocks);
    script << OP_CHECKLOCKTIMEVERIFY;
    script << OP_DROP;
    
    // Extract pubkey hash from sender script if P2PKH
    if (Solver(senderScript, type, solutions) && type == TX_PUBKEYHASH) {
        script << OP_DUP << OP_HASH160;
        script << solutions[0];
        script << OP_EQUALVERIFY << OP_CHECKSIG;
    } else {
        script << senderScript;
    }
    
    script << OP_ENDIF;
    
    return script;
}

CScript CreateClaimScript(
    const std::vector<unsigned char>& preimage,
    const std::vector<unsigned char>& signature,
    const std::vector<unsigned char>& pubkey)
{
    // To claim: <sig> <pubkey> <preimage> OP_TRUE
    CScript script;
    script << signature;
    script << pubkey;
    script << preimage;
    script << OP_TRUE;
    return script;
}

CScript CreateRefundScript(
    const std::vector<unsigned char>& signature,
    const std::vector<unsigned char>& pubkey)
{
    // To refund: <sig> <pubkey> OP_FALSE
    CScript script;
    script << signature;
    script << pubkey;
    script << OP_FALSE;
    return script;
}

bool ExtractPreimage(
    const CScript& scriptSig,
    std::vector<unsigned char>& preimage)
{
    // Parse the scriptSig to find the preimage
    // In our format: <sig> <pubkey> <preimage> OP_TRUE
    std::vector<std::vector<unsigned char>> stack;
    
    CScript::const_iterator pc = scriptSig.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    
    while (pc < scriptSig.end()) {
        if (!scriptSig.GetOp(pc, opcode, data)) {
            return false;
        }
        if (opcode <= OP_PUSHDATA4) {
            stack.push_back(data);
        }
    }
    
    // We expect: sig, pubkey, preimage, then OP_TRUE
    // The preimage should be the third push (index 2)
    if (stack.size() >= 3) {
        preimage = stack[2];
        return true;
    }
    
    return false;
}

} // namespace HTLCScript

// ============================================================================
// CAtomicSwapOrderBook Implementation
// ============================================================================

bool CAtomicSwapOrderBook::AddOffer(const CAtomicSwapOffer& offer)
{
    LOCK(cs);
    
    if (offers.count(offer.offerHash)) {
        return false; // Already exists
    }
    
    offers[offer.offerHash] = offer;
    
    // Index by trading pair
    std::string pairKey = GetTradingPairKey(offer.makerAssetName, offer.takerAssetName);
    offersByPair[pairKey].insert(offer.offerHash);
    
    LogPrintf("CAtomicSwapOrderBook::%s -- Added offer: %s\n", __func__, offer.ToString());
    return true;
}

bool CAtomicSwapOrderBook::RemoveOffer(const uint256& offerHash)
{
    LOCK(cs);
    
    auto it = offers.find(offerHash);
    if (it == offers.end()) {
        return false;
    }
    
    const CAtomicSwapOffer& offer = it->second;
    std::string pairKey = GetTradingPairKey(offer.makerAssetName, offer.takerAssetName);
    offersByPair[pairKey].erase(offerHash);
    
    offers.erase(it);
    
    LogPrintf("CAtomicSwapOrderBook::%s -- Removed offer: %s\n", __func__, offerHash.ToString());
    return true;
}

CAtomicSwapOffer* CAtomicSwapOrderBook::GetOffer(const uint256& offerHash)
{
    LOCK(cs);
    
    auto it = offers.find(offerHash);
    if (it == offers.end()) {
        return nullptr;
    }
    return &it->second;
}

std::vector<CAtomicSwapOffer> CAtomicSwapOrderBook::GetOffersForPair(
    const std::string& assetA, 
    const std::string& assetB) const
{
    LOCK(cs);
    
    std::vector<CAtomicSwapOffer> result;
    std::string pairKey = GetTradingPairKey(assetA, assetB);
    
    auto it = offersByPair.find(pairKey);
    if (it == offersByPair.end()) {
        return result;
    }
    
    for (const uint256& hash : it->second) {
        auto offerIt = offers.find(hash);
        if (offerIt != offers.end() && offerIt->second.isActive) {
            result.push_back(offerIt->second);
        }
    }
    
    return result;
}

CAtomicSwapOffer* CAtomicSwapOrderBook::GetBestOffer(
    const std::string& wantAsset,
    const std::string& haveAsset,
    bool buyOrder)
{
    LOCK(cs);
    
    std::string pairKey = GetTradingPairKey(wantAsset, haveAsset);
    
    auto it = offersByPair.find(pairKey);
    if (it == offersByPair.end()) {
        return nullptr;
    }
    
    CAtomicSwapOffer* bestOffer = nullptr;
    double bestRate = buyOrder ? std::numeric_limits<double>::max() : 0;
    
    for (const uint256& hash : it->second) {
        auto offerIt = offers.find(hash);
        if (offerIt == offers.end() || !offerIt->second.isActive) {
            continue;
        }
        
        CAtomicSwapOffer& offer = offerIt->second;
        
        // Check if offer matches our direction
        bool offerMatchesDirection = 
            (buyOrder && offer.makerAssetName == wantAsset) ||
            (!buyOrder && offer.takerAssetName == wantAsset);
        
        if (!offerMatchesDirection) {
            continue;
        }
        
        double rate = offer.GetRate();
        if (buyOrder) {
            // Buying: want lowest rate
            if (rate < bestRate) {
                bestRate = rate;
                bestOffer = &offer;
            }
        } else {
            // Selling: want highest rate
            if (rate > bestRate) {
                bestRate = rate;
                bestOffer = &offer;
            }
        }
    }
    
    return bestOffer;
}

void CAtomicSwapOrderBook::CleanupExpired(int currentHeight)
{
    LOCK(cs);
    
    std::vector<uint256> toRemove;
    
    for (const auto& pair : offers) {
        if (pair.second.IsExpired(currentHeight)) {
            toRemove.push_back(pair.first);
        }
    }
    
    for (const uint256& hash : toRemove) {
        RemoveOffer(hash);
    }
    
    if (!toRemove.empty()) {
        LogPrintf("CAtomicSwapOrderBook::%s -- Cleaned up %d expired offers\n", 
                  __func__, toRemove.size());
    }
}

UniValue CAtomicSwapOrderBook::GetOrderBookJson(
    const std::string& assetA,
    const std::string& assetB) const
{
    LOCK(cs);
    
    UniValue result(UniValue::VOBJ);
    UniValue bids(UniValue::VARR);  // Buy orders for assetA
    UniValue asks(UniValue::VARR);  // Sell orders for assetA
    
    auto allOffers = GetOffersForPair(assetA, assetB);
    
    for (const auto& offer : allOffers) {
        UniValue offerJson(UniValue::VOBJ);
        offerJson.pushKV("hash", offer.offerHash.ToString());
        offerJson.pushKV("makerAsset", offer.makerAssetName.empty() ? "MYNTA" : offer.makerAssetName);
        offerJson.pushKV("makerAmount", offer.makerAmount);
        offerJson.pushKV("takerAsset", offer.takerAssetName.empty() ? "MYNTA" : offer.takerAssetName);
        offerJson.pushKV("takerAmount", offer.takerAmount);
        offerJson.pushKV("rate", offer.GetRate());
        offerJson.pushKV("createdHeight", offer.createdHeight);
        offerJson.pushKV("expiresHeight", offer.createdHeight + offer.timeoutBlocks);
        
        // Determine if this is a bid or ask relative to assetA
        if (offer.makerAssetName == assetA || 
            (offer.makerAssetName.empty() && assetA.empty())) {
            asks.push_back(offerJson);  // Selling assetA
        } else {
            bids.push_back(offerJson);  // Buying assetA
        }
    }
    
    result.pushKV("pair", assetA + "/" + (assetB.empty() ? "MYNTA" : assetB));
    result.pushKV("bids", bids);
    result.pushKV("asks", asks);
    
    return result;
}

// ============================================================================
// Validation Functions
// ============================================================================

bool CheckAtomicSwapOffer(const CAtomicSwapOffer& offer, std::string& strError)
{
    if (offer.makerAmount <= 0) {
        strError = "Maker amount must be positive";
        return false;
    }
    
    if (offer.takerAmount <= 0) {
        strError = "Taker amount must be positive";
        return false;
    }
    
    if (offer.timeoutBlocks < 10) {
        strError = "Timeout must be at least 10 blocks";
        return false;
    }
    
    if (offer.timeoutBlocks > 5040) { // ~3.5 days at 1 min blocks
        strError = "Timeout must be less than 5040 blocks";
        return false;
    }
    
    if (offer.makerAddress.empty()) {
        strError = "Maker address is required";
        return false;
    }
    
    return true;
}

bool CheckHTLC(const CHTLC& htlc, std::string& strError)
{
    if (htlc.amount <= 0) {
        strError = "Amount must be positive";
        return false;
    }
    
    if (htlc.senderAddress.empty()) {
        strError = "Sender address is required";
        return false;
    }
    
    if (htlc.receiverAddress.empty()) {
        strError = "Receiver address is required";
        return false;
    }
    
    if (htlc.hashLock.IsNull()) {
        strError = "Hash lock is required";
        return false;
    }
    
    return true;
}

// ============================================================================
// Helper Functions
// ============================================================================

uint256 GenerateSwapSecret()
{
    uint256 secret;
    GetRandBytes(secret.begin(), 32);
    return secret;
}

uint256 HashSecret(const std::vector<unsigned char>& secret)
{
    uint256 hash;
    CSHA256().Write(secret.data(), secret.size()).Finalize(hash.begin());
    return hash;
}

std::string GetTradingPairKey(const std::string& assetA, const std::string& assetB)
{
    // Normalize: use "MYNTA" for empty string, sort alphabetically
    std::string a = assetA.empty() ? "MYNTA" : assetA;
    std::string b = assetB.empty() ? "MYNTA" : assetB;
    
    if (a > b) {
        std::swap(a, b);
    }
    
    return a + ":" + b;
}

