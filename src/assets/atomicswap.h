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

// ============================================================================
// HTLC Transaction Builders
// ============================================================================

class CWallet;
class CReserveKey;

namespace HTLCTransactions {

/**
 * Result structure for HTLC operations
 */
struct HTLCResult {
    bool success{false};
    std::string error;
    uint256 txHash;
    CHTLC htlc;
    std::vector<unsigned char> preimage;  // Populated on create/claim
    
    HTLCResult() = default;
    explicit HTLCResult(const std::string& err) : success(false), error(err) {}
    static HTLCResult Success(const uint256& hash) {
        HTLCResult r;
        r.success = true;
        r.txHash = hash;
        return r;
    }
};

/**
 * Create an HTLC transaction
 * 
 * @param wallet The wallet to use for funding
 * @param receiverAddress The address that can claim with preimage
 * @param amount The amount to lock
 * @param assetName The asset name (empty for MYNTA)
 * @param timeoutBlocks Number of blocks until refund allowed
 * @param hashLock The SHA256 hash of the preimage (if empty, generates new secret)
 * @return HTLCResult with transaction details and preimage (if generated)
 */
HTLCResult CreateHTLC(
    CWallet* wallet,
    const CTxDestination& receiverAddress,
    CAmount amount,
    const std::string& assetName,
    uint32_t timeoutBlocks,
    const uint256& hashLock = uint256()
);

/**
 * Claim an HTLC by revealing the preimage
 * 
 * @param wallet The wallet to use
 * @param htlcTxHash The transaction hash containing the HTLC
 * @param htlcOutputIndex The output index of the HTLC
 * @param preimage The secret preimage that hashes to hashLock
 * @param destinationAddress Where to send the claimed funds
 * @return HTLCResult with claim transaction details
 */
HTLCResult ClaimHTLC(
    CWallet* wallet,
    const uint256& htlcTxHash,
    int htlcOutputIndex,
    const std::vector<unsigned char>& preimage,
    const CTxDestination& destinationAddress
);

/**
 * Refund an HTLC after timeout
 * 
 * @param wallet The wallet to use
 * @param htlcTxHash The transaction hash containing the HTLC
 * @param htlcOutputIndex The output index of the HTLC
 * @param destinationAddress Where to send the refunded funds
 * @return HTLCResult with refund transaction details
 */
HTLCResult RefundHTLC(
    CWallet* wallet,
    const uint256& htlcTxHash,
    int htlcOutputIndex,
    const CTxDestination& destinationAddress
);

/**
 * Parse an HTLC from a transaction output
 * 
 * @param script The scriptPubKey of the output
 * @param htlc Output HTLC structure
 * @return true if successfully parsed as HTLC
 */
bool ParseHTLCScript(const CScript& script, CHTLC& htlc);

/**
 * Verify that an HTLC output matches expected parameters
 * 
 * @param tx The transaction to verify
 * @param outputIndex The output index
 * @param expectedHashLock The expected hash lock
 * @param expectedAmount The expected amount
 * @param strError Output error message
 * @return true if valid
 */
bool VerifyHTLCOutput(
    const CTransaction& tx,
    int outputIndex,
    const uint256& expectedHashLock,
    CAmount expectedAmount,
    std::string& strError
);

/**
 * Get the current timeout status of an HTLC
 * 
 * @param htlcTxHash The HTLC transaction hash
 * @param htlcOutputIndex The output index
 * @param blocksRemaining Output: blocks until timeout (negative if expired)
 * @param canClaim Output: true if HTLC can be claimed
 * @param canRefund Output: true if HTLC can be refunded
 * @return true if HTLC found and status determined
 */
bool GetHTLCStatus(
    const uint256& htlcTxHash,
    int htlcOutputIndex,
    int& blocksRemaining,
    bool& canClaim,
    bool& canRefund
);

} // namespace HTLCTransactions

// ============================================================================
// Persistent Order Book with Reorg Safety
// ============================================================================

class CDBWrapper;

/**
 * CPersistentOrderBook - Persistent, reorg-safe order book storage
 */
class CPersistentOrderBook
{
private:
    mutable CCriticalSection cs;
    std::unique_ptr<CDBWrapper> db;
    
    // In-memory cache synchronized with disk
    std::map<uint256, CAtomicSwapOffer> offers;
    std::map<std::string, std::set<uint256>> offersByPair;
    
    // UTXO tracking for reorg safety
    // Maps offer hash to the UTXO that locks it
    std::map<uint256, COutPoint> offerUTXOs;
    
    // Height tracking for deterministic pruning
    int currentHeight{0};

public:
    explicit CPersistentOrderBook(const std::string& dbPath);
    ~CPersistentOrderBook();
    
    // Initialize/load from disk
    bool Initialize();
    
    // Basic operations
    bool AddOffer(const CAtomicSwapOffer& offer, const COutPoint& fundingUTXO);
    bool RemoveOffer(const uint256& offerHash);
    bool MarkOfferFilled(const uint256& offerHash, const uint256& fillTxHash);
    bool CancelOffer(const uint256& offerHash);
    
    // Lookup
    bool GetOffer(const uint256& offerHash, CAtomicSwapOffer& offer) const;
    std::vector<CAtomicSwapOffer> GetOffersForPair(const std::string& assetA, const std::string& assetB) const;
    std::vector<CAtomicSwapOffer> GetActiveOffers() const;
    
    // Block processing (for reorg safety)
    void ConnectBlock(const CBlock& block, int height);
    void DisconnectBlock(const CBlock& block, int height);
    
    // UTXO monitoring
    void UTXOSpent(const COutPoint& utxo);
    bool IsOfferUTXOSpent(const uint256& offerHash) const;
    
    // Maintenance
    void CleanupExpired(int currentHeight);
    void Flush();
    
    // Queries
    UniValue GetOrderBookJson(const std::string& assetA, const std::string& assetB) const;
    int GetOfferCount() const;
    int GetCurrentHeight() const { return currentHeight; }
};

// Global persistent order book
extern std::unique_ptr<CPersistentOrderBook> persistentOrderBook;

// Initialize persistent order book
bool InitPersistentOrderBook(const std::string& datadir);
void StopPersistentOrderBook();

#endif // MYNTA_ASSETS_ATOMICSWAP_H

