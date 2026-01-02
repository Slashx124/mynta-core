// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MYNTA_ASSETS_ATOMICSWAP_H
#define MYNTA_ASSETS_ATOMICSWAP_H

#include "amount.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "serialize.h"
#include "uint256.h"

#include <string>
#include <vector>

/**
 * Atomic Swap Protocol for Mynta Assets
 * 
 * This implements Hash Time-Locked Contracts (HTLCs) for trustless asset swaps.
 * 
 * Use Cases:
 * 1. MYNTA <-> Asset swaps (on-chain DEX)
 * 2. Asset <-> Asset swaps
 * 3. Cross-chain atomic swaps (with external chains)
 * 
 * HTLC Structure:
 * - Hash lock: SHA256 preimage required to claim
 * - Time lock: Refund possible after timeout
 * - Dual signatures: Both parties can verify
 */

// HTLC script type identifiers
enum class HTLCType : uint8_t {
    MYNTA_TO_ASSET = 0,
    ASSET_TO_MYNTA = 1,
    ASSET_TO_ASSET = 2,
};

/**
 * CAtomicSwapOffer - Represents a swap offer on the order book
 */
class CAtomicSwapOffer
{
public:
    uint256 offerHash;              // Unique offer identifier
    
    // What the maker is offering
    std::string makerAssetName;     // Empty string = MYNTA
    CAmount makerAmount;
    CScript makerAddress;
    
    // What the maker wants
    std::string takerAssetName;     // Empty string = MYNTA
    CAmount takerAmount;
    
    // HTLC parameters
    uint256 hashLock;               // SHA256 hash of secret
    uint32_t timeoutBlocks;         // Blocks until refund allowed
    int createdHeight;              // Block height when created
    
    // State
    bool isActive{true};
    bool isFilled{false};
    uint256 fillTxHash;             // Transaction that filled the offer
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(offerHash);
        READWRITE(makerAssetName);
        READWRITE(makerAmount);
        READWRITE(makerAddress);
        READWRITE(takerAssetName);
        READWRITE(takerAmount);
        READWRITE(hashLock);
        READWRITE(timeoutBlocks);
        READWRITE(createdHeight);
        READWRITE(isActive);
        READWRITE(isFilled);
        READWRITE(fillTxHash);
    }

    // Calculate the exchange rate (taker/maker)
    double GetRate() const;
    
    // Check if the offer has expired
    bool IsExpired(int currentHeight) const;
    
    std::string ToString() const;
};

/**
 * CHTLC - Hash Time-Locked Contract
 */
class CHTLC
{
public:
    uint256 htlcId;                 // Unique HTLC identifier
    
    // Participants
    CScript senderAddress;          // Can refund after timeout
    CScript receiverAddress;        // Can claim with preimage
    
    // Lock conditions
    uint256 hashLock;               // SHA256(preimage) - receiver must reveal
    uint32_t timeLock;              // Absolute block height for timeout
    
    // Value
    std::string assetName;          // Empty = MYNTA
    CAmount amount;
    
    // State
    enum State : uint8_t {
        PENDING = 0,
        CLAIMED = 1,
        REFUNDED = 2,
        EXPIRED = 3,
    };
    State state{PENDING};
    
    // Claim/Refund data
    uint256 claimTxHash;
    std::vector<unsigned char> preimage;  // Revealed when claimed
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(htlcId);
        READWRITE(senderAddress);
        READWRITE(receiverAddress);
        READWRITE(hashLock);
        READWRITE(timeLock);
        READWRITE(assetName);
        READWRITE(amount);
        READWRITE(state);
        READWRITE(claimTxHash);
        READWRITE(preimage);
    }

    // Generate the HTLC redeem script
    CScript GetRedeemScript() const;
    
    // Generate the P2SH address for this HTLC
    CScript GetP2SHScript() const;
    
    // Verify a preimage against the hash lock
    bool VerifyPreimage(const std::vector<unsigned char>& testPreimage) const;
    
    // Check if HTLC can be refunded (timed out)
    bool CanRefund(int currentHeight) const;
    
    std::string ToString() const;
};

/**
 * CAtomicSwap - A complete atomic swap between two parties
 */
class CAtomicSwap
{
public:
    uint256 swapId;
    
    // The two HTLCs that make up the swap
    CHTLC makerHtlc;                // Maker's HTLC (created first)
    CHTLC takerHtlc;                // Taker's HTLC (created second)
    
    // Swap state
    enum State : uint8_t {
        INITIATED = 0,              // Maker created HTLC
        MATCHED = 1,                // Taker created matching HTLC
        COMPLETED = 2,              // Both parties claimed
        REFUNDED = 3,               // One or both parties refunded
        FAILED = 4,                 // Swap failed
    };
    State state{INITIATED};
    
    // Timestamps
    int initiatedHeight;
    int matchedHeight;
    int completedHeight;
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(swapId);
        READWRITE(makerHtlc);
        READWRITE(takerHtlc);
        READWRITE(state);
        READWRITE(initiatedHeight);
        READWRITE(matchedHeight);
        READWRITE(completedHeight);
    }

    std::string ToString() const;
};

// HTLC Script Generation
namespace HTLCScript {
    /**
     * Generate an HTLC redeem script:
     * 
     * OP_IF
     *     OP_SHA256 <hash> OP_EQUALVERIFY
     *     <receiver_pubkey> OP_CHECKSIG
     * OP_ELSE
     *     <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
     *     <sender_pubkey> OP_CHECKSIG
     * OP_ENDIF
     */
    CScript CreateHTLCScript(
        const std::vector<unsigned char>& hashLock,
        const CScript& receiverScript,
        const CScript& senderScript,
        uint32_t timeoutBlocks
    );
    
    /**
     * Create the claim script (reveal preimage)
     */
    CScript CreateClaimScript(
        const std::vector<unsigned char>& preimage,
        const std::vector<unsigned char>& signature,
        const std::vector<unsigned char>& pubkey
    );
    
    /**
     * Create the refund script (after timeout)
     */
    CScript CreateRefundScript(
        const std::vector<unsigned char>& signature,
        const std::vector<unsigned char>& pubkey
    );
    
    /**
     * Extract the preimage from a claim transaction
     */
    bool ExtractPreimage(
        const CScript& scriptSig,
        std::vector<unsigned char>& preimage
    );
}

// Order Book Management
class CAtomicSwapOrderBook
{
private:
    mutable CCriticalSection cs;
    
    // Active offers indexed by hash
    std::map<uint256, CAtomicSwapOffer> offers;
    
    // Offers indexed by asset pair for quick lookup
    // Key: "ASSET_A:ASSET_B" (sorted alphabetically)
    std::map<std::string, std::set<uint256>> offersByPair;

public:
    // Add a new offer
    bool AddOffer(const CAtomicSwapOffer& offer);
    
    // Remove an offer
    bool RemoveOffer(const uint256& offerHash);
    
    // Get an offer by hash
    CAtomicSwapOffer* GetOffer(const uint256& offerHash);
    
    // Get all offers for a trading pair
    std::vector<CAtomicSwapOffer> GetOffersForPair(
        const std::string& assetA, 
        const std::string& assetB
    ) const;
    
    // Get best offer for a trading pair
    CAtomicSwapOffer* GetBestOffer(
        const std::string& wantAsset,
        const std::string& haveAsset,
        bool buyOrder  // true = buy wantAsset, false = sell wantAsset
    );
    
    // Clean up expired offers
    void CleanupExpired(int currentHeight);
    
    // Get order book summary
    UniValue GetOrderBookJson(
        const std::string& assetA,
        const std::string& assetB
    ) const;
};

// Global order book
extern std::unique_ptr<CAtomicSwapOrderBook> atomicSwapOrderBook;

// Validation functions
bool CheckAtomicSwapOffer(const CAtomicSwapOffer& offer, std::string& strError);
bool CheckHTLC(const CHTLC& htlc, std::string& strError);

// Helper functions
uint256 GenerateSwapSecret();
uint256 HashSecret(const std::vector<unsigned char>& secret);
std::string GetTradingPairKey(const std::string& assetA, const std::string& assetB);

#endif // MYNTA_ASSETS_ATOMICSWAP_H

