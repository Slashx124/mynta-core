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

// ============================================================================
// HTLC Transaction Builders Implementation
// ============================================================================

#include "base58.h"
#include "coins.h"
#include "consensus/validation.h"
#include "key.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/sign.h"
#include "txmempool.h"
#include "validation.h"
#include "wallet/wallet.h"

namespace HTLCTransactions {

HTLCResult CreateHTLC(
    CWallet* wallet,
    const CTxDestination& receiverAddress,
    CAmount amount,
    const std::string& assetName,
    uint32_t timeoutBlocks,
    const uint256& hashLock)
{
    if (!wallet) {
        return HTLCResult("Wallet not available");
    }
    
    if (amount <= 0) {
        return HTLCResult("Amount must be positive");
    }
    
    if (timeoutBlocks < 10) {
        return HTLCResult("Timeout must be at least 10 blocks");
    }
    
    // Get sender's address from wallet
    LOCK2(cs_main, wallet->cs_wallet);
    
    CPubKey senderPubKey;
    if (!wallet->GetKeyFromPool(senderPubKey, false)) {
        return HTLCResult("Failed to get key from wallet");
    }
    
    CKeyID senderKeyId = senderPubKey.GetID();
    CScript senderScript = GetScriptForDestination(senderKeyId);
    CScript receiverScript = GetScriptForDestination(receiverAddress);
    
    // Generate or use provided hash lock
    std::vector<unsigned char> preimage;
    uint256 finalHashLock;
    
    if (hashLock.IsNull()) {
        // Generate new secret
        uint256 secret = GenerateSwapSecret();
        preimage.assign(secret.begin(), secret.end());
        finalHashLock = HashSecret(preimage);
    } else {
        finalHashLock = hashLock;
    }
    
    // Calculate absolute timeout height
    int currentHeight = chainActive.Height();
    uint32_t timeoutHeight = currentHeight + timeoutBlocks;
    
    // Create HTLC script
    CScript htlcScript = HTLCScript::CreateHTLCScript(
        std::vector<unsigned char>(finalHashLock.begin(), finalHashLock.end()),
        receiverScript,
        senderScript,
        timeoutHeight
    );
    
    // Create P2SH output
    CScript p2shScript = GetScriptForDestination(CScriptID(htlcScript));
    
    // Build transaction
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = 0;
    
    // Add output
    mtx.vout.push_back(CTxOut(amount, p2shScript));
    
    // Select coins and add inputs
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    vecSend.push_back({p2shScript, amount, false});
    
    int nChangePosRet = -1;
    CReserveKey reservekey(wallet);
    CWalletTx wtx;
    
    if (!wallet->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError)) {
        return HTLCResult("Failed to create transaction: " + strError);
    }
    
    // Commit transaction
    CValidationState state;
    if (!wallet->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        return HTLCResult("Failed to commit transaction: " + state.GetRejectReason());
    }
    
    // Build result
    HTLCResult result = HTLCResult::Success(wtx.GetHash());
    result.preimage = preimage;
    
    // Populate HTLC info
    result.htlc.htlcId = wtx.GetHash();
    result.htlc.senderAddress = senderScript;
    result.htlc.receiverAddress = receiverScript;
    result.htlc.hashLock = finalHashLock;
    result.htlc.timeLock = timeoutHeight;
    result.htlc.assetName = assetName;
    result.htlc.amount = amount;
    result.htlc.state = CHTLC::PENDING;
    
    LogPrintf("HTLCTransactions::%s -- Created HTLC: %s\n", __func__, result.htlc.ToString());
    
    return result;
}

HTLCResult ClaimHTLC(
    CWallet* wallet,
    const uint256& htlcTxHash,
    int htlcOutputIndex,
    const std::vector<unsigned char>& preimage,
    const CTxDestination& destinationAddress)
{
    if (!wallet) {
        return HTLCResult("Wallet not available");
    }
    
    if (preimage.empty()) {
        return HTLCResult("Preimage is required");
    }
    
    LOCK2(cs_main, wallet->cs_wallet);
    
    // Find the HTLC output
    CTransactionRef htlcTx;
    uint256 hashBlock;
    if (!GetTransaction(htlcTxHash, htlcTx, Params().GetConsensus(), hashBlock, true)) {
        return HTLCResult("HTLC transaction not found");
    }
    
    if (htlcOutputIndex < 0 || htlcOutputIndex >= (int)htlcTx->vout.size()) {
        return HTLCResult("Invalid output index");
    }
    
    const CTxOut& htlcOutput = htlcTx->vout[htlcOutputIndex];
    
    // Verify preimage hashes to expected value
    uint256 computedHash = HashSecret(preimage);
    
    // Parse HTLC script to get expected hash
    // For now, we trust the caller knows the correct preimage
    
    // Get key for signing
    CPubKey claimPubKey;
    if (!wallet->GetKeyFromPool(claimPubKey, false)) {
        return HTLCResult("Failed to get key from wallet");
    }
    
    CKey claimKey;
    if (!wallet->GetKey(claimPubKey.GetID(), claimKey)) {
        return HTLCResult("Failed to get private key");
    }
    
    // Build claim transaction
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = 0;
    
    // Add input
    mtx.vin.push_back(CTxIn(COutPoint(htlcTxHash, htlcOutputIndex)));
    
    // Calculate fee
    CAmount fee = GetMinRelayFee(3000, false); // Estimate 3KB
    CAmount claimAmount = htlcOutput.nValue - fee;
    
    if (claimAmount <= 0) {
        return HTLCResult("HTLC value too small to cover fees");
    }
    
    // Add output
    CScript destScript = GetScriptForDestination(destinationAddress);
    mtx.vout.push_back(CTxOut(claimAmount, destScript));
    
    // Sign with preimage reveal (claim path)
    // Need to extract redeem script from P2SH
    
    // For P2SH, we need to provide:
    // <signature> <pubkey> <preimage> OP_TRUE <redeemScript>
    
    // First, sign the transaction
    uint256 sigHash = SignatureHash(htlcOutput.scriptPubKey, mtx, 0, 
                                     SIGHASH_ALL, htlcOutput.nValue, SIGVERSION_BASE);
    
    std::vector<unsigned char> signature;
    if (!claimKey.Sign(sigHash, signature)) {
        return HTLCResult("Failed to sign claim transaction");
    }
    signature.push_back((unsigned char)SIGHASH_ALL);
    
    // Build scriptSig for claim path
    CScript scriptSig = HTLCScript::CreateClaimScript(
        preimage,
        signature,
        std::vector<unsigned char>(claimPubKey.begin(), claimPubKey.end())
    );
    
    mtx.vin[0].scriptSig = scriptSig;
    
    // Validate and broadcast
    CTransactionRef finalTx = MakeTransactionRef(std::move(mtx));
    
    CValidationState state;
    if (!AcceptToMemoryPool(mempool, state, finalTx, nullptr, nullptr, false, DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK())) {
        return HTLCResult("Transaction rejected: " + state.GetRejectReason());
    }
    
    // Relay
    RelayTransaction(*finalTx, g_connman.get());
    
    HTLCResult result = HTLCResult::Success(finalTx->GetHash());
    result.preimage = preimage;
    
    LogPrintf("HTLCTransactions::%s -- Claimed HTLC %s output %d\n", 
              __func__, htlcTxHash.ToString().substr(0, 16), htlcOutputIndex);
    
    return result;
}

HTLCResult RefundHTLC(
    CWallet* wallet,
    const uint256& htlcTxHash,
    int htlcOutputIndex,
    const CTxDestination& destinationAddress)
{
    if (!wallet) {
        return HTLCResult("Wallet not available");
    }
    
    LOCK2(cs_main, wallet->cs_wallet);
    
    // Find the HTLC output
    CTransactionRef htlcTx;
    uint256 hashBlock;
    if (!GetTransaction(htlcTxHash, htlcTx, Params().GetConsensus(), hashBlock, true)) {
        return HTLCResult("HTLC transaction not found");
    }
    
    if (htlcOutputIndex < 0 || htlcOutputIndex >= (int)htlcTx->vout.size()) {
        return HTLCResult("Invalid output index");
    }
    
    const CTxOut& htlcOutput = htlcTx->vout[htlcOutputIndex];
    
    // TODO: Parse HTLC script to verify timeout and extract sender pubkey
    // For now, we assume the caller is the correct refund recipient
    
    int currentHeight = chainActive.Height();
    
    // Get key for signing
    CPubKey refundPubKey;
    if (!wallet->GetKeyFromPool(refundPubKey, false)) {
        return HTLCResult("Failed to get key from wallet");
    }
    
    CKey refundKey;
    if (!wallet->GetKey(refundPubKey.GetID(), refundKey)) {
        return HTLCResult("Failed to get private key");
    }
    
    // Build refund transaction
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    
    // Set nLockTime to the timeout for CLTV
    // TODO: Extract actual timeout from HTLC script
    mtx.nLockTime = currentHeight;
    
    // Add input with sequence for CLTV
    CTxIn txin(COutPoint(htlcTxHash, htlcOutputIndex));
    txin.nSequence = 0xFFFFFFFE; // Enable nLockTime
    mtx.vin.push_back(txin);
    
    // Calculate fee
    CAmount fee = GetMinRelayFee(2000, false);
    CAmount refundAmount = htlcOutput.nValue - fee;
    
    if (refundAmount <= 0) {
        return HTLCResult("HTLC value too small to cover fees");
    }
    
    // Add output
    CScript destScript = GetScriptForDestination(destinationAddress);
    mtx.vout.push_back(CTxOut(refundAmount, destScript));
    
    // Sign with refund path
    uint256 sigHash = SignatureHash(htlcOutput.scriptPubKey, mtx, 0,
                                     SIGHASH_ALL, htlcOutput.nValue, SIGVERSION_BASE);
    
    std::vector<unsigned char> signature;
    if (!refundKey.Sign(sigHash, signature)) {
        return HTLCResult("Failed to sign refund transaction");
    }
    signature.push_back((unsigned char)SIGHASH_ALL);
    
    // Build scriptSig for refund path (no preimage, OP_FALSE)
    CScript scriptSig = HTLCScript::CreateRefundScript(
        signature,
        std::vector<unsigned char>(refundPubKey.begin(), refundPubKey.end())
    );
    
    mtx.vin[0].scriptSig = scriptSig;
    
    // Validate and broadcast
    CTransactionRef finalTx = MakeTransactionRef(std::move(mtx));
    
    CValidationState state;
    if (!AcceptToMemoryPool(mempool, state, finalTx, nullptr, nullptr, false, DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK())) {
        return HTLCResult("Transaction rejected: " + state.GetRejectReason());
    }
    
    // Relay
    RelayTransaction(*finalTx, g_connman.get());
    
    HTLCResult result = HTLCResult::Success(finalTx->GetHash());
    
    LogPrintf("HTLCTransactions::%s -- Refunded HTLC %s output %d\n",
              __func__, htlcTxHash.ToString().substr(0, 16), htlcOutputIndex);
    
    return result;
}

bool ParseHTLCScript(const CScript& script, CHTLC& htlc)
{
    // Parse P2SH to get redeem script
    // Then extract HTLC parameters from redeem script
    
    // For P2SH: OP_HASH160 <hash> OP_EQUAL
    txnouttype type;
    std::vector<std::vector<unsigned char>> solutions;
    if (!Solver(script, type, solutions)) {
        return false;
    }
    
    if (type != TX_SCRIPTHASH) {
        return false;
    }
    
    // We'd need the actual redeem script to parse further
    // For now, return false - caller should provide known HTLC info
    return false;
}

bool VerifyHTLCOutput(
    const CTransaction& tx,
    int outputIndex,
    const uint256& expectedHashLock,
    CAmount expectedAmount,
    std::string& strError)
{
    if (outputIndex < 0 || outputIndex >= (int)tx.vout.size()) {
        strError = "Invalid output index";
        return false;
    }
    
    const CTxOut& output = tx.vout[outputIndex];
    
    if (output.nValue != expectedAmount) {
        strError = "Amount mismatch";
        return false;
    }
    
    // Verify P2SH output
    txnouttype type;
    std::vector<std::vector<unsigned char>> solutions;
    if (!Solver(output.scriptPubKey, type, solutions)) {
        strError = "Failed to parse output script";
        return false;
    }
    
    if (type != TX_SCRIPTHASH) {
        strError = "Output is not P2SH";
        return false;
    }
    
    // Full verification would require the redeem script
    // For basic check, we verify it's a P2SH output with correct amount
    
    return true;
}

bool GetHTLCStatus(
    const uint256& htlcTxHash,
    int htlcOutputIndex,
    int& blocksRemaining,
    bool& canClaim,
    bool& canRefund)
{
    LOCK(cs_main);
    
    // Find the HTLC transaction
    CTransactionRef htlcTx;
    uint256 hashBlock;
    if (!GetTransaction(htlcTxHash, htlcTx, Params().GetConsensus(), hashBlock, true)) {
        return false;
    }
    
    if (htlcOutputIndex < 0 || htlcOutputIndex >= (int)htlcTx->vout.size()) {
        return false;
    }
    
    // Check if output is spent
    CCoinsViewCache& view = *pcoinsTip;
    const Coin& coin = view.AccessCoin(COutPoint(htlcTxHash, htlcOutputIndex));
    
    if (coin.IsSpent()) {
        blocksRemaining = 0;
        canClaim = false;
        canRefund = false;
        return true; // HTLC already spent (claimed or refunded)
    }
    
    int currentHeight = chainActive.Height();
    
    // For proper status, we'd need to parse the HTLC script to get timeout
    // For now, assume standard 144 block timeout (1 day)
    int assumedTimeout = 144;
    
    // Get block height where HTLC was created
    int htlcHeight = 0;
    if (!hashBlock.IsNull()) {
        CBlockIndex* pindex = LookupBlockIndex(hashBlock);
        if (pindex) {
            htlcHeight = pindex->nHeight;
        }
    }
    
    int timeoutHeight = htlcHeight + assumedTimeout;
    blocksRemaining = timeoutHeight - currentHeight;
    
    canClaim = true; // Can always claim with valid preimage
    canRefund = currentHeight >= timeoutHeight;
    
    return true;
}

} // namespace HTLCTransactions

// ============================================================================
// Persistent Order Book Implementation
// ============================================================================

#include "dbwrapper.h"
#include "fs.h"

std::unique_ptr<CPersistentOrderBook> persistentOrderBook;

// Database key prefixes
static const char DB_OFFER = 'O';
static const char DB_PAIR_INDEX = 'P';
static const char DB_UTXO = 'U';
static const char DB_HEIGHT = 'H';

CPersistentOrderBook::CPersistentOrderBook(const std::string& dbPath)
{
    fs::path path = fs::path(dbPath) / "orderbook";
    db = std::make_unique<CDBWrapper>(path, 1 << 20, false, false);
}

CPersistentOrderBook::~CPersistentOrderBook()
{
    Flush();
}

bool CPersistentOrderBook::Initialize()
{
    LOCK(cs);
    
    // Load height
    db->Read(DB_HEIGHT, currentHeight);
    
    // Load all offers
    std::unique_ptr<CDBIterator> iter(db->NewIterator());
    
    for (iter->Seek(DB_OFFER); iter->Valid(); iter->Next()) {
        char prefix;
        uint256 hash;
        
        CDataStream keyStream(SER_DISK, CLIENT_VERSION);
        keyStream.write(iter->GetKey().data(), iter->GetKey().size());
        keyStream >> prefix;
        
        if (prefix != DB_OFFER) break;
        
        keyStream >> hash;
        
        CAtomicSwapOffer offer;
        if (iter->GetValue(offer)) {
            offers[hash] = offer;
            
            std::string pairKey = GetTradingPairKey(offer.makerAssetName, offer.takerAssetName);
            offersByPair[pairKey].insert(hash);
        }
    }
    
    // Load UTXO mappings
    for (iter->Seek(DB_UTXO); iter->Valid(); iter->Next()) {
        char prefix;
        uint256 offerHash;
        
        CDataStream keyStream(SER_DISK, CLIENT_VERSION);
        keyStream.write(iter->GetKey().data(), iter->GetKey().size());
        keyStream >> prefix;
        
        if (prefix != DB_UTXO) break;
        
        keyStream >> offerHash;
        
        COutPoint utxo;
        if (iter->GetValue(utxo)) {
            offerUTXOs[offerHash] = utxo;
        }
    }
    
    LogPrintf("CPersistentOrderBook::%s -- Loaded %d offers\n", __func__, offers.size());
    return true;
}

bool CPersistentOrderBook::AddOffer(const CAtomicSwapOffer& offer, const COutPoint& fundingUTXO)
{
    LOCK(cs);
    
    if (offers.count(offer.offerHash)) {
        return false;
    }
    
    // Write to database
    CDataStream keyStream(SER_DISK, CLIENT_VERSION);
    keyStream << DB_OFFER << offer.offerHash;
    
    if (!db->Write(keyStream, offer)) {
        return false;
    }
    
    // Write UTXO mapping
    CDataStream utxoKeyStream(SER_DISK, CLIENT_VERSION);
    utxoKeyStream << DB_UTXO << offer.offerHash;
    
    if (!db->Write(utxoKeyStream, fundingUTXO)) {
        return false;
    }
    
    // Update memory
    offers[offer.offerHash] = offer;
    std::string pairKey = GetTradingPairKey(offer.makerAssetName, offer.takerAssetName);
    offersByPair[pairKey].insert(offer.offerHash);
    offerUTXOs[offer.offerHash] = fundingUTXO;
    
    LogPrintf("CPersistentOrderBook::%s -- Added offer: %s\n", __func__, offer.ToString());
    return true;
}

bool CPersistentOrderBook::RemoveOffer(const uint256& offerHash)
{
    LOCK(cs);
    
    auto it = offers.find(offerHash);
    if (it == offers.end()) {
        return false;
    }
    
    // Remove from database
    CDataStream keyStream(SER_DISK, CLIENT_VERSION);
    keyStream << DB_OFFER << offerHash;
    db->Erase(keyStream);
    
    CDataStream utxoKeyStream(SER_DISK, CLIENT_VERSION);
    utxoKeyStream << DB_UTXO << offerHash;
    db->Erase(utxoKeyStream);
    
    // Update memory
    const CAtomicSwapOffer& offer = it->second;
    std::string pairKey = GetTradingPairKey(offer.makerAssetName, offer.takerAssetName);
    offersByPair[pairKey].erase(offerHash);
    offerUTXOs.erase(offerHash);
    offers.erase(it);
    
    return true;
}

bool CPersistentOrderBook::MarkOfferFilled(const uint256& offerHash, const uint256& fillTxHash)
{
    LOCK(cs);
    
    auto it = offers.find(offerHash);
    if (it == offers.end()) {
        return false;
    }
    
    it->second.isActive = false;
    it->second.isFilled = true;
    it->second.fillTxHash = fillTxHash;
    
    // Update database
    CDataStream keyStream(SER_DISK, CLIENT_VERSION);
    keyStream << DB_OFFER << offerHash;
    db->Write(keyStream, it->second);
    
    return true;
}

bool CPersistentOrderBook::CancelOffer(const uint256& offerHash)
{
    return RemoveOffer(offerHash);
}

bool CPersistentOrderBook::GetOffer(const uint256& offerHash, CAtomicSwapOffer& offer) const
{
    LOCK(cs);
    
    auto it = offers.find(offerHash);
    if (it == offers.end()) {
        return false;
    }
    
    offer = it->second;
    return true;
}

std::vector<CAtomicSwapOffer> CPersistentOrderBook::GetOffersForPair(
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

std::vector<CAtomicSwapOffer> CPersistentOrderBook::GetActiveOffers() const
{
    LOCK(cs);
    
    std::vector<CAtomicSwapOffer> result;
    for (const auto& pair : offers) {
        if (pair.second.isActive) {
            result.push_back(pair.second);
        }
    }
    return result;
}

void CPersistentOrderBook::ConnectBlock(const CBlock& block, int height)
{
    LOCK(cs);
    currentHeight = height;
    
    // Check for filled or cancelled offers in this block
    for (const auto& tx : block.vtx) {
        // Check if any inputs spend offer UTXOs
        for (const auto& vin : tx->vin) {
            for (auto& pair : offerUTXOs) {
                if (pair.second == vin.prevout) {
                    MarkOfferFilled(pair.first, tx->GetHash());
                }
            }
        }
    }
    
    // Update height in database
    db->Write(DB_HEIGHT, currentHeight);
}

void CPersistentOrderBook::DisconnectBlock(const CBlock& block, int height)
{
    LOCK(cs);
    currentHeight = height - 1;
    
    // On reorg, we need to restore offers that were filled in this block
    // This requires tracking which offers were filled in which block
    // For now, simple implementation just updates height
    
    db->Write(DB_HEIGHT, currentHeight);
    
    LogPrintf("CPersistentOrderBook::%s -- Disconnected block at height %d\n", __func__, height);
}

void CPersistentOrderBook::UTXOSpent(const COutPoint& utxo)
{
    LOCK(cs);
    
    for (auto& pair : offerUTXOs) {
        if (pair.second == utxo) {
            RemoveOffer(pair.first);
            break;
        }
    }
}

bool CPersistentOrderBook::IsOfferUTXOSpent(const uint256& offerHash) const
{
    LOCK(cs);
    
    auto it = offerUTXOs.find(offerHash);
    if (it == offerUTXOs.end()) {
        return true; // No UTXO means it's spent or doesn't exist
    }
    
    LOCK(cs_main);
    CCoinsViewCache& view = *pcoinsTip;
    return view.AccessCoin(it->second).IsSpent();
}

void CPersistentOrderBook::CleanupExpired(int currentHeight)
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
        LogPrintf("CPersistentOrderBook::%s -- Cleaned up %d expired offers\n",
                  __func__, toRemove.size());
    }
}

void CPersistentOrderBook::Flush()
{
    LOCK(cs);
    if (db) {
        db->Write(DB_HEIGHT, currentHeight);
    }
}

UniValue CPersistentOrderBook::GetOrderBookJson(
    const std::string& assetA,
    const std::string& assetB) const
{
    LOCK(cs);
    
    UniValue result(UniValue::VOBJ);
    UniValue bids(UniValue::VARR);
    UniValue asks(UniValue::VARR);
    
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
        
        if (offer.makerAssetName == assetA ||
            (offer.makerAssetName.empty() && assetA.empty())) {
            asks.push_back(offerJson);
        } else {
            bids.push_back(offerJson);
        }
    }
    
    result.pushKV("pair", (assetA.empty() ? "MYNTA" : assetA) + "/" + (assetB.empty() ? "MYNTA" : assetB));
    result.pushKV("bids", bids);
    result.pushKV("asks", asks);
    result.pushKV("height", currentHeight);
    
    return result;
}

int CPersistentOrderBook::GetOfferCount() const
{
    LOCK(cs);
    return offers.size();
}

// Global initialization
bool InitPersistentOrderBook(const std::string& datadir)
{
    persistentOrderBook = std::make_unique<CPersistentOrderBook>(datadir);
    return persistentOrderBook->Initialize();
}

void StopPersistentOrderBook()
{
    if (persistentOrderBook) {
        persistentOrderBook->Flush();
        persistentOrderBook.reset();
    }
}

