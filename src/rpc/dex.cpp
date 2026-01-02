// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assets/atomicswap.h"
#include "assets/assets.h"
#include "base58.h"
#include "chain.h"
#include "core_io.h"
#include "hash.h"
#include "init.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "util.h"
#include "validation.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <univalue.h>

// ============================================================================
// Order Book RPC Commands
// ============================================================================

UniValue dex_orderbook(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "dex orderbook \"base_asset\" ( \"quote_asset\" )\n"
            "\nGet the order book for a trading pair.\n"
            "\nArguments:\n"
            "1. \"base_asset\"     (string, required) The base asset (or \"MYNTA\")\n"
            "2. \"quote_asset\"    (string, optional, default=\"MYNTA\") The quote asset\n"
            "\nResult:\n"
            "{\n"
            "  \"pair\": \"BASE/QUOTE\",\n"
            "  \"bids\": [...],\n"
            "  \"asks\": [...]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("dex", "orderbook \"MYTOKEN\"")
            + HelpExampleCli("dex", "orderbook \"MYTOKEN\" \"MYNTA\"")
        );

    std::string baseAsset = request.params[0].get_str();
    std::string quoteAsset = "MYNTA";
    
    if (request.params.size() >= 2) {
        quoteAsset = request.params[1].get_str();
    }
    
    // Normalize "MYNTA" to empty string for internal use
    if (baseAsset == "MYNTA") baseAsset = "";
    if (quoteAsset == "MYNTA") quoteAsset = "";
    
    if (!atomicSwapOrderBook) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Order book not initialized");
    }
    
    return atomicSwapOrderBook->GetOrderBookJson(baseAsset, quoteAsset);
}

UniValue dex_createoffer(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 4)
        throw std::runtime_error(
            "dex createoffer \"sell_asset\" sell_amount \"buy_asset\" buy_amount ( timeout_blocks )\n"
            "\nCreate a new swap offer on the DEX.\n"
            "\nArguments:\n"
            "1. \"sell_asset\"     (string, required) Asset to sell (or \"MYNTA\")\n"
            "2. sell_amount        (numeric, required) Amount to sell\n"
            "3. \"buy_asset\"      (string, required) Asset to buy (or \"MYNTA\")\n"
            "4. buy_amount         (numeric, required) Amount to buy\n"
            "5. timeout_blocks     (numeric, optional, default=1440) Blocks until offer expires\n"
            "\nResult:\n"
            "{\n"
            "  \"offerHash\": \"hash\",\n"
            "  \"secret\": \"hex\",\n"
            "  \"hashLock\": \"hash\"\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("dex", "createoffer \"MYTOKEN\" 100 \"MYNTA\" 50")
        );

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    std::string sellAsset = request.params[0].get_str();
    CAmount sellAmount = AmountFromValue(request.params[1]);
    std::string buyAsset = request.params[2].get_str();
    CAmount buyAmount = AmountFromValue(request.params[3]);
    uint32_t timeoutBlocks = 1440; // ~24 hours at 1 min blocks
    
    if (request.params.size() >= 5) {
        timeoutBlocks = request.params[4].get_int();
    }
    
    // Normalize asset names
    if (sellAsset == "MYNTA") sellAsset = "";
    if (buyAsset == "MYNTA") buyAsset = "";
    
    // Generate secret and hash lock
    uint256 secret = GenerateSwapSecret();
    uint256 hashLock = HashSecret(std::vector<unsigned char>(secret.begin(), secret.end()));
    
    // Get a fresh address for the maker
    CPubKey makerKey;
    if (!pwallet->GetKeyFromPool(makerKey, false)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Keypool ran out");
    }
    CScript makerAddress = GetScriptForDestination(makerKey.GetID());
    
    // Create the offer
    CAtomicSwapOffer offer;
    offer.makerAssetName = sellAsset;
    offer.makerAmount = sellAmount;
    offer.makerAddress = makerAddress;
    offer.takerAssetName = buyAsset;
    offer.takerAmount = buyAmount;
    offer.hashLock = hashLock;
    offer.timeoutBlocks = timeoutBlocks;
    offer.createdHeight = chainActive.Height();
    offer.isActive = true;
    
    // Generate offer hash
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << offer.makerAssetName;
    hw << offer.makerAmount;
    hw << offer.takerAssetName;
    hw << offer.takerAmount;
    hw << offer.hashLock;
    hw << offer.createdHeight;
    offer.offerHash = hw.GetHash();
    
    // Validate
    std::string strError;
    if (!CheckAtomicSwapOffer(offer, strError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strError);
    }
    
    // Add to order book
    if (!atomicSwapOrderBook) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Order book not initialized");
    }
    
    if (!atomicSwapOrderBook->AddOffer(offer)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to add offer to order book");
    }
    
    UniValue result(UniValue::VOBJ);
    result.pushKV("offerHash", offer.offerHash.ToString());
    result.pushKV("secret", HexStr(secret));
    result.pushKV("hashLock", hashLock.ToString());
    result.pushKV("sellAsset", sellAsset.empty() ? "MYNTA" : sellAsset);
    result.pushKV("sellAmount", ValueFromAmount(sellAmount));
    result.pushKV("buyAsset", buyAsset.empty() ? "MYNTA" : buyAsset);
    result.pushKV("buyAmount", ValueFromAmount(buyAmount));
    result.pushKV("expiresHeight", static_cast<int64_t>(offer.createdHeight) + timeoutBlocks);
    
    return result;
#else
    throw JSONRPCError(RPC_WALLET_ERROR, "Wallet support not compiled in");
#endif
}

UniValue dex_takeoffer(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1)
        throw std::runtime_error(
            "dex takeoffer \"offer_hash\"\n"
            "\nAccept a swap offer from the DEX order book.\n"
            "\nArguments:\n"
            "1. \"offer_hash\"     (string, required) The hash of the offer to accept\n"
            "\nResult:\n"
            "{\n"
            "  \"htlcTxid\": \"txid\",\n"
            "  \"status\": \"pending\"\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("dex", "takeoffer \"abc123...\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    uint256 offerHash = ParseHashV(request.params[0], "offer_hash");
    
    if (!atomicSwapOrderBook) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Order book not initialized");
    }
    
    CAtomicSwapOffer* offer = atomicSwapOrderBook->GetOffer(offerHash);
    if (!offer) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer not found");
    }
    
    if (!offer->isActive) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer is no longer active");
    }
    
    if (offer->IsExpired(chainActive.Height())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer has expired");
    }
    
    // TODO: Create the HTLC transaction to lock taker's funds
    // This would create a P2SH output with the HTLC script
    
    UniValue result(UniValue::VOBJ);
    result.pushKV("offerHash", offerHash.ToString());
    result.pushKV("status", "accepted");
    result.pushKV("note", "HTLC creation will be implemented in next phase");
    
    return result;
#else
    throw JSONRPCError(RPC_WALLET_ERROR, "Wallet support not compiled in");
#endif
}

UniValue dex_canceloffer(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "dex canceloffer \"offer_hash\"\n"
            "\nCancel a swap offer you created.\n"
            "\nArguments:\n"
            "1. \"offer_hash\"     (string, required) The hash of the offer to cancel\n"
            "\nResult:\n"
            "{\n"
            "  \"cancelled\": true\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("dex", "canceloffer \"abc123...\"")
        );

    uint256 offerHash = ParseHashV(request.params[0], "offer_hash");
    
    if (!atomicSwapOrderBook) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Order book not initialized");
    }
    
    if (!atomicSwapOrderBook->RemoveOffer(offerHash)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Offer not found or already removed");
    }
    
    UniValue result(UniValue::VOBJ);
    result.pushKV("cancelled", true);
    result.pushKV("offerHash", offerHash.ToString());
    
    return result;
}

UniValue dex_listtrades(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "dex listtrades ( \"asset\" count )\n"
            "\nList recent trades.\n"
            "\nArguments:\n"
            "1. \"asset\"     (string, optional) Filter by asset\n"
            "2. count         (numeric, optional, default=50) Number of trades to return\n"
            "\nResult:\n"
            "[...]\n"
            "\nExamples:\n"
            + HelpExampleCli("dex", "listtrades")
        );

    // TODO: Implement trade history
    UniValue result(UniValue::VARR);
    return result;
}

// ============================================================================
// HTLC RPC Commands
// ============================================================================

UniValue htlc_create(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4)
        throw std::runtime_error(
            "htlc create \"receiver_address\" amount \"hash_lock\" timeout_blocks ( \"asset\" )\n"
            "\nCreate a Hash Time-Locked Contract.\n"
            "\nArguments:\n"
            "1. \"receiver_address\"  (string, required) Address that can claim with preimage\n"
            "2. amount                (numeric, required) Amount to lock\n"
            "3. \"hash_lock\"         (string, required) SHA256 hash of the secret (hex)\n"
            "4. timeout_blocks        (numeric, required) Blocks until refund is possible\n"
            "5. \"asset\"             (string, optional) Asset name (default: MYNTA)\n"
            "\nResult:\n"
            "{\n"
            "  \"htlcAddress\": \"address\",\n"
            "  \"redeemScript\": \"hex\"\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("htlc", "create \"Maddr...\" 10 \"abcd1234...\" 720")
        );

    std::string receiverAddr = request.params[0].get_str();
    CAmount amount = AmountFromValue(request.params[1]);
    std::vector<unsigned char> hashLock = ParseHex(request.params[2].get_str());
    uint32_t timeoutBlocks = request.params[3].get_int();
    std::string assetName = "";
    
    if (request.params.size() >= 5) {
        assetName = request.params[4].get_str();
        if (assetName == "MYNTA") assetName = "";
    }
    
    // Validate hash lock size
    if (hashLock.size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Hash lock must be 32 bytes (SHA256)");
    }
    
    // Parse receiver address
    CTxDestination receiverDest = DecodeDestination(receiverAddr);
    if (!IsValidDestination(receiverDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid receiver address");
    }
    CScript receiverScript = GetScriptForDestination(receiverDest);
    
    // For now, use a placeholder sender script
    // In production, this would come from the wallet
    CScript senderScript = receiverScript; // Placeholder
    
    // Calculate absolute timeout height
    LOCK(cs_main);
    uint32_t absoluteTimeout = chainActive.Height() + timeoutBlocks;
    
    // Generate HTLC script
    CScript htlcScript = HTLCScript::CreateHTLCScript(
        hashLock,
        receiverScript,
        senderScript,
        absoluteTimeout
    );
    
    // Get P2SH address
    CScriptID htlcScriptId(htlcScript);
    CTxDestination htlcDest(htlcScriptId);
    
    UniValue result(UniValue::VOBJ);
    result.pushKV("htlcAddress", EncodeDestination(htlcDest));
    result.pushKV("redeemScript", HexStr(htlcScript));
    result.pushKV("amount", ValueFromAmount(amount));
    result.pushKV("asset", assetName.empty() ? "MYNTA" : assetName);
    result.pushKV("timeoutHeight", (int)absoluteTimeout);
    
    return result;
}

UniValue htlc_claim(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2)
        throw std::runtime_error(
            "htlc claim \"htlc_txid\" \"preimage\"\n"
            "\nClaim funds from an HTLC by revealing the preimage.\n"
            "\nArguments:\n"
            "1. \"htlc_txid\"     (string, required) HTLC transaction ID\n"
            "2. \"preimage\"      (string, required) The preimage (hex)\n"
            "\nResult:\n"
            "\"txid\"             (string) The claim transaction ID\n"
            "\nExamples:\n"
            + HelpExampleCli("htlc", "claim \"abc123...\" \"secret123...\"")
        );

    // TODO: Implement claim transaction creation
    throw JSONRPCError(RPC_MISC_ERROR, "Not yet implemented");
}

UniValue htlc_refund(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1)
        throw std::runtime_error(
            "htlc refund \"htlc_txid\"\n"
            "\nRefund funds from an expired HTLC.\n"
            "\nArguments:\n"
            "1. \"htlc_txid\"     (string, required) HTLC transaction ID\n"
            "\nResult:\n"
            "\"txid\"             (string) The refund transaction ID\n"
            "\nExamples:\n"
            + HelpExampleCli("htlc", "refund \"abc123...\"")
        );

    // TODO: Implement refund transaction creation
    throw JSONRPCError(RPC_MISC_ERROR, "Not yet implemented");
}

// ============================================================================
// Command Dispatcher
// ============================================================================

UniValue dex(const JSONRPCRequest& request)
{
    std::string strCommand;
    if (request.params.size() >= 1) {
        strCommand = request.params[0].get_str();
    }

    if (request.fHelp && strCommand.empty()) {
        throw std::runtime_error(
            "dex \"command\" ...\n"
            "\nDecentralized exchange commands for atomic swaps.\n"
            "\nAvailable commands:\n"
            "  orderbook     - View the order book for a trading pair\n"
            "  createoffer   - Create a new swap offer\n"
            "  takeoffer     - Accept an existing offer\n"
            "  canceloffer   - Cancel your offer\n"
            "  listtrades    - List recent trades\n"
        );
    }

    JSONRPCRequest newRequest = request;
    newRequest.params = UniValue(UniValue::VARR);
    for (size_t i = 1; i < request.params.size(); i++) {
        newRequest.params.push_back(request.params[i]);
    }

    if (strCommand == "orderbook") {
        return dex_orderbook(newRequest);
    } else if (strCommand == "createoffer") {
        return dex_createoffer(newRequest);
    } else if (strCommand == "takeoffer") {
        return dex_takeoffer(newRequest);
    } else if (strCommand == "canceloffer") {
        return dex_canceloffer(newRequest);
    } else if (strCommand == "listtrades") {
        return dex_listtrades(newRequest);
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown dex command: " + strCommand);
}

UniValue htlc(const JSONRPCRequest& request)
{
    std::string strCommand;
    if (request.params.size() >= 1) {
        strCommand = request.params[0].get_str();
    }

    if (request.fHelp && strCommand.empty()) {
        throw std::runtime_error(
            "htlc \"command\" ...\n"
            "\nHash Time-Locked Contract commands.\n"
            "\nAvailable commands:\n"
            "  create   - Create a new HTLC\n"
            "  claim    - Claim funds with preimage\n"
            "  refund   - Refund after timeout\n"
        );
    }

    JSONRPCRequest newRequest = request;
    newRequest.params = UniValue(UniValue::VARR);
    for (size_t i = 1; i < request.params.size(); i++) {
        newRequest.params.push_back(request.params[i]);
    }

    if (strCommand == "create") {
        return htlc_create(newRequest);
    } else if (strCommand == "claim") {
        return htlc_claim(newRequest);
    } else if (strCommand == "refund") {
        return htlc_refund(newRequest);
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown htlc command: " + strCommand);
}

// ============================================================================
// RPC Registration
// ============================================================================

static const CRPCCommand commands[] =
{
    //  category              name        actor (function)     argNames
    //  --------------------- ----------- -------------------- --------
    { "dex",                 "dex",       &dex,                {} },
    { "dex",                 "htlc",      &htlc,               {} },
};

void RegisterDexRPCCommands(CRPCTable& t)
{
    for (unsigned int i = 0; i < ARRAYLEN(commands); i++) {
        t.appendCommand(commands[i].name, &commands[i]);
    }
}

