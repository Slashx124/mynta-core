// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "chain.h"
#include "chainparams.h"
#include "core_io.h"
#include "evo/deterministicmns.h"
#include "evo/providertx.h"
#include "init.h"
#include "net.h"
#include "netbase.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "util.h"
#include "validation.h"

#ifdef ENABLE_WALLET
#include "wallet/coincontrol.h"
#include "wallet/wallet.h"
#endif

#include <univalue.h>

static UniValue MNToJson(const CDeterministicMNCPtr& mn)
{
    UniValue obj(UniValue::VOBJ);
    
    obj.pushKV("proTxHash", mn->proTxHash.ToString());
    obj.pushKV("collateralHash", mn->collateralOutpoint.hash.ToString());
    obj.pushKV("collateralIndex", (int)mn->collateralOutpoint.n);
    obj.pushKV("operatorReward", mn->nOperatorReward / 100.0);
    
    // State
    UniValue stateObj(UniValue::VOBJ);
    stateObj.pushKV("registeredHeight", mn->state.nRegisteredHeight);
    stateObj.pushKV("lastPaidHeight", mn->state.nLastPaidHeight);
    stateObj.pushKV("PoSePenalty", mn->state.nPoSePenalty);
    stateObj.pushKV("PoSeRevivedHeight", mn->state.nPoSeRevivedHeight);
    stateObj.pushKV("PoSeBanHeight", mn->state.nPoSeBanHeight);
    stateObj.pushKV("revocationReason", (int)mn->state.nRevocationReason);
    stateObj.pushKV("ownerAddress", EncodeDestination(mn->state.keyIDOwner));
    stateObj.pushKV("votingAddress", EncodeDestination(mn->state.keyIDVoting));
    stateObj.pushKV("service", mn->state.addr.ToString());
    
    CTxDestination payoutDest;
    if (ExtractDestination(mn->state.scriptPayout, payoutDest)) {
        stateObj.pushKV("payoutAddress", EncodeDestination(payoutDest));
    }
    
    obj.pushKV("state", stateObj);
    
    // Status
    std::string status;
    if (mn->state.nRevocationReason != 0) {
        status = "REVOKED";
    } else if (mn->state.IsBanned()) {
        status = "POSE_BANNED";
    } else if (!mn->IsValid()) {
        status = "INVALID";
    } else {
        status = "ENABLED";
    }
    obj.pushKV("status", status);
    
    return obj;
}

UniValue masternode_list(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "masternode list ( \"mode\" \"filter\" )\n"
            "\nGet a list of masternodes in different modes.\n"
            "\nArguments:\n"
            "1. \"mode\"      (string, optional, default = \"json\") The mode of the list.\n"
            "                 Available modes:\n"
            "                   json   - Returns a JSON object with all masternode details\n"
            "                   addr   - Returns list of masternode addresses\n"
            "                   full   - Returns detailed info\n"
            "2. \"filter\"    (string, optional) Filter output by substring\n"
            "\nResult:\n"
            "Depends on mode\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode", "list")
            + HelpExampleCli("masternode", "list json")
            + HelpExampleRpc("masternode", "list, \"json\"")
        );

    std::string strMode = "json";
    std::string strFilter = "";

    if (request.params.size() >= 1) {
        strMode = request.params[0].get_str();
    }
    if (request.params.size() >= 2) {
        strFilter = request.params[1].get_str();
    }

    if (!deterministicMNManager) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Masternode manager not initialized");
    }

    auto mnList = deterministicMNManager->GetListAtChainTip();

    if (strMode == "json") {
        UniValue result(UniValue::VARR);
        mnList->ForEachMN(false, [&](const CDeterministicMNCPtr& mn) {
            UniValue obj = MNToJson(mn);
            
            // Apply filter if specified
            if (!strFilter.empty()) {
                std::string jsonStr = obj.write();
                if (jsonStr.find(strFilter) == std::string::npos) {
                    return;
                }
            }
            
            result.push_back(obj);
        });
        return result;
    } else if (strMode == "addr") {
        UniValue result(UniValue::VARR);
        mnList->ForEachMN(true, [&](const CDeterministicMNCPtr& mn) {
            std::string addr = mn->state.addr.ToString();
            if (strFilter.empty() || addr.find(strFilter) != std::string::npos) {
                result.push_back(addr);
            }
        });
        return result;
    } else if (strMode == "full") {
        UniValue result(UniValue::VOBJ);
        mnList->ForEachMN(false, [&](const CDeterministicMNCPtr& mn) {
            std::string key = mn->proTxHash.ToString().substr(0, 16);
            result.pushKV(key, MNToJson(mn));
        });
        return result;
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode: " + strMode);
}

UniValue masternode_count(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
            "masternode count\n"
            "\nGet masternode count values.\n"
            "\nResult:\n"
            "{\n"
            "  \"total\": n,      (numeric) Total masternodes\n"
            "  \"enabled\": n,    (numeric) Enabled masternodes\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode", "count")
            + HelpExampleRpc("masternode", "count")
        );

    if (!deterministicMNManager) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Masternode manager not initialized");
    }

    auto mnList = deterministicMNManager->GetListAtChainTip();

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("total", (int)mnList->GetAllMNsCount());
    obj.pushKV("enabled", (int)mnList->GetValidMNsCount());
    
    return obj;
}

UniValue masternode_winner(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "masternode winner ( count )\n"
            "\nPrint info on next masternode winner(s) to vote for.\n"
            "\nArguments:\n"
            "1. count      (numeric, optional, default=10) number of next winners\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"height\": n,           (numeric) block height\n"
            "    \"proTxHash\": \"hash\",   (string) masternode proTxHash\n"
            "    \"payoutAddress\": \"addr\" (string) payout address\n"
            "  },...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode", "winner")
            + HelpExampleCli("masternode", "winner 20")
        );

    int nCount = 10;
    if (request.params.size() >= 1) {
        nCount = request.params[0].get_int();
        if (nCount < 1 || nCount > 100) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Count must be between 1 and 100");
        }
    }

    if (!deterministicMNManager) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Masternode manager not initialized");
    }

    LOCK(cs_main);

    UniValue result(UniValue::VARR);
    
    const CBlockIndex* pindex = chainActive.Tip();
    if (!pindex) {
        return result;
    }

    auto mnList = deterministicMNManager->GetListForBlock(pindex);
    if (!mnList || mnList->GetValidMNsCount() == 0) {
        return result;
    }

    // Predict winners for next blocks
    for (int i = 1; i <= nCount; i++) {
        int futureHeight = pindex->nHeight + i;
        
        // Use a predictable hash for future blocks
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
        hw << pindex->GetBlockHash();
        hw << futureHeight;
        uint256 futureHash = hw.GetHash();
        
        auto winner = mnList->GetMNPayee(futureHash);
        if (winner) {
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("height", futureHeight);
            obj.pushKV("proTxHash", winner->proTxHash.ToString());
            
            CTxDestination dest;
            if (ExtractDestination(winner->state.scriptPayout, dest)) {
                obj.pushKV("payoutAddress", EncodeDestination(dest));
            }
            
            result.push_back(obj);
        }
    }

    return result;
}

UniValue protx_register(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 6)
        throw std::runtime_error(
            "protx register \"collateralHash\" collateralIndex \"ipAndPort\" \"ownerAddress\" \"operatorPubKey\" \"votingAddress\" operatorReward \"payoutAddress\" ( \"fundAddress\" )\n"
            "\nCreates and sends a ProRegTx to the network.\n"
            "\nArguments:\n"
            "1. \"collateralHash\"     (string, required) The hash of the collateral transaction\n"
            "2. collateralIndex        (numeric, required) The output index of the collateral\n"
            "3. \"ipAndPort\"          (string, required) IP and port in format \"IP:PORT\"\n"
            "4. \"ownerAddress\"       (string, required) The owner key address (P2PKH)\n"
            "5. \"operatorPubKey\"     (string, required) The operator BLS public key (hex)\n"
            "6. \"votingAddress\"      (string, required) The voting key address (P2PKH)\n"
            "7. operatorReward         (numeric, required) Operator reward percentage (0-100)\n"
            "8. \"payoutAddress\"      (string, required) The payout address (P2PKH or P2SH)\n"
            "9. \"fundAddress\"        (string, optional) Fund the transaction from this address\n"
            "\nResult:\n"
            "\"txid\"                  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("protx", "register \"abc123...\" 0 \"192.168.1.1:8770\" \"Mabc...\" \"0123...\" \"Mxyz...\" 0 \"Mpay...\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    // Parse arguments
    uint256 collateralHash = ParseHashV(request.params[0], "collateralHash");
    int collateralIndex = request.params[1].get_int();
    std::string strIpPort = request.params[2].get_str();
    std::string strOwnerAddress = request.params[3].get_str();
    std::string strOperatorPubKey = request.params[4].get_str();
    std::string strVotingAddress = request.params[5].get_str();
    double operatorReward = request.params[6].get_real();
    std::string strPayoutAddress = request.params[7].get_str();

    // Validate operator reward
    if (operatorReward < 0 || operatorReward > 100) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Operator reward must be between 0 and 100");
    }

    // Parse IP:Port
    CService addr;
    if (!Lookup(strIpPort.c_str(), addr, 0, false)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid IP:Port: %s", strIpPort));
    }

    // Parse addresses
    CTxDestination ownerDest = DecodeDestination(strOwnerAddress);
    if (!IsValidDestination(ownerDest) || !boost::get<CKeyID>(&ownerDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid owner address");
    }
    CKeyID ownerKeyId = boost::get<CKeyID>(ownerDest);

    CTxDestination votingDest = DecodeDestination(strVotingAddress);
    if (!IsValidDestination(votingDest) || !boost::get<CKeyID>(&votingDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid voting address");
    }
    CKeyID votingKeyId = boost::get<CKeyID>(votingDest);

    CTxDestination payoutDest = DecodeDestination(strPayoutAddress);
    if (!IsValidDestination(payoutDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid payout address");
    }

    // Parse operator public key (hex)
    std::vector<unsigned char> vchOperatorPubKey = ParseHex(strOperatorPubKey);
    if (vchOperatorPubKey.size() != 48) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Operator public key must be 48 bytes (BLS)");
    }

    // Build ProRegTx payload
    CProRegTx proTx;
    proTx.nVersion = CProRegTx::CURRENT_VERSION;
    proTx.collateralOutpoint = COutPoint(collateralHash, collateralIndex);
    proTx.addr = addr;
    proTx.keyIDOwner = ownerKeyId;
    proTx.vchOperatorPubKey = vchOperatorPubKey;
    proTx.keyIDVoting = votingKeyId;
    proTx.nOperatorReward = (uint16_t)(operatorReward * 100);
    proTx.scriptPayout = GetScriptForDestination(payoutDest);

    // Build the transaction
    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = static_cast<uint16_t>(TxType::TRANSACTION_PROVIDER_REGISTER);

    // Add an input to fund the transaction (fee only, collateral is external)
    CAmount nFee = 0.001 * COIN; // TODO: Calculate proper fee
    
    // Select coins for fee
    std::vector<COutput> vAvailableCoins;
    pwallet->AvailableCoins(vAvailableCoins);
    
    CAmount nValueIn = 0;
    for (const auto& out : vAvailableCoins) {
        if (out.tx->tx->vout[out.i].nValue >= nFee) {
            tx.vin.push_back(CTxIn(out.tx->GetHash(), out.i));
            nValueIn = out.tx->tx->vout[out.i].nValue;
            break;
        }
    }

    if (nValueIn == 0) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds for fee");
    }

    // Add change output
    CReserveKey reservekey(pwallet);
    CPubKey changeKey;
    if (!reservekey.GetReservedKey(changeKey, true)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Keypool ran out");
    }
    CScript changeScript = GetScriptForDestination(changeKey.GetID());
    tx.vout.push_back(CTxOut(nValueIn - nFee, changeScript));

    // Calculate inputs hash
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    for (const auto& input : tx.vin) {
        hw << input.prevout;
    }
    proTx.inputsHash = hw.GetHash();

    // Sign the payload with owner key
    CKey ownerKey;
    if (!pwallet->GetKey(ownerKeyId, ownerKey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Owner key not found in wallet");
    }
    
    uint256 sigHash = proTx.GetSignatureHash();
    if (!ownerKey.SignCompact(sigHash, proTx.vchSig)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign ProRegTx");
    }

    // Set the payload
    SetTxPayload(tx, proTx);

    // Sign the transaction inputs
    int nIn = 0;
    for (const auto& input : tx.vin) {
        const CWalletTx* wtx = pwallet->GetWalletTx(input.prevout.hash);
        if (!wtx) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Input not found in wallet");
        }
        
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(pwallet, &tx, nIn, 
                              wtx->tx->vout[input.prevout.n].nValue, SIGHASH_ALL),
                              wtx->tx->vout[input.prevout.n].scriptPubKey, sigdata)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction input");
        }
        UpdateTransaction(tx, nIn, sigdata);
        nIn++;
    }

    // Submit the transaction
    CWalletTx wtx;
    wtx.fTimeReceivedIsTxTime = true;
    wtx.BindWallet(pwallet);
    wtx.SetTx(MakeTransactionRef(std::move(tx)));

    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to commit transaction: %s", state.GetRejectReason()));
    }

    return wtx.GetHash().ToString();
#else
    throw JSONRPCError(RPC_WALLET_ERROR, "Wallet support not compiled in");
#endif
}

UniValue protx_list(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "protx list ( \"type\" detailed )\n"
            "\nLists all ProTxs.\n"
            "\nArguments:\n"
            "1. \"type\"      (string, optional, default=\"registered\") Type of list:\n"
            "                 \"registered\" - All registered masternodes\n"
            "                 \"valid\"      - Only valid/enabled masternodes\n"
            "2. detailed      (bool, optional, default=false) Show detailed info\n"
            "\nResult:\n"
            "[...]\n"
            "\nExamples:\n"
            + HelpExampleCli("protx", "list")
            + HelpExampleCli("protx", "list registered true")
        );

    std::string type = "registered";
    bool detailed = false;

    if (request.params.size() >= 1) {
        type = request.params[0].get_str();
    }
    if (request.params.size() >= 2) {
        detailed = request.params[1].get_bool();
    }

    if (!deterministicMNManager) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Masternode manager not initialized");
    }

    auto mnList = deterministicMNManager->GetListAtChainTip();
    bool onlyValid = (type == "valid");

    UniValue result(UniValue::VARR);
    mnList->ForEachMN(onlyValid, [&](const CDeterministicMNCPtr& mn) {
        if (detailed) {
            result.push_back(MNToJson(mn));
        } else {
            result.push_back(mn->proTxHash.ToString());
        }
    });

    return result;
}

UniValue protx_info(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "protx info \"proTxHash\"\n"
            "\nReturns detailed information about a specific ProTx.\n"
            "\nArguments:\n"
            "1. \"proTxHash\"    (string, required) The hash of the ProTx\n"
            "\nResult:\n"
            "{...}             (json object) Detailed masternode info\n"
            "\nExamples:\n"
            + HelpExampleCli("protx", "info \"abc123...\"")
        );

    uint256 proTxHash = ParseHashV(request.params[0], "proTxHash");

    if (!deterministicMNManager) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Masternode manager not initialized");
    }

    auto mn = deterministicMNManager->GetMN(proTxHash);
    if (!mn) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ProTx not found");
    }

    return MNToJson(mn);
}

// Command dispatcher
UniValue masternode(const JSONRPCRequest& request)
{
    std::string strCommand;
    if (request.params.size() >= 1) {
        strCommand = request.params[0].get_str();
    }

    if (request.fHelp && strCommand.empty()) {
        throw std::runtime_error(
            "masternode \"command\" ...\n"
            "\nSet of commands to execute masternode related actions\n"
            "\nArguments:\n"
            "1. \"command\"        (string, required) The command to execute\n"
            "\nAvailable commands:\n"
            "  count        - Get masternode count\n"
            "  list         - Get list of masternodes\n"
            "  winner       - Get next masternode winner(s)\n"
        );
    }

    // Forward to specific command
    JSONRPCRequest newRequest = request;
    newRequest.params = UniValue(UniValue::VARR);
    for (size_t i = 1; i < request.params.size(); i++) {
        newRequest.params.push_back(request.params[i]);
    }

    if (strCommand == "count") {
        return masternode_count(newRequest);
    } else if (strCommand == "list") {
        return masternode_list(newRequest);
    } else if (strCommand == "winner") {
        return masternode_winner(newRequest);
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown masternode command: " + strCommand);
}

UniValue protx(const JSONRPCRequest& request)
{
    std::string strCommand;
    if (request.params.size() >= 1) {
        strCommand = request.params[0].get_str();
    }

    if (request.fHelp && strCommand.empty()) {
        throw std::runtime_error(
            "protx \"command\" ...\n"
            "\nSet of commands to manage ProTx transactions\n"
            "\nArguments:\n"
            "1. \"command\"        (string, required) The command to execute\n"
            "\nAvailable commands:\n"
            "  register     - Register a new masternode\n"
            "  list         - List ProTx registrations\n"
            "  info         - Get info about a specific ProTx\n"
        );
    }

    // Forward to specific command
    JSONRPCRequest newRequest = request;
    newRequest.params = UniValue(UniValue::VARR);
    for (size_t i = 1; i < request.params.size(); i++) {
        newRequest.params.push_back(request.params[i]);
    }

    if (strCommand == "register") {
        return protx_register(newRequest);
    } else if (strCommand == "list") {
        return protx_list(newRequest);
    } else if (strCommand == "info") {
        return protx_info(newRequest);
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown protx command: " + strCommand);
}

// Register RPC commands
static const CRPCCommand commands[] =
{
    //  category              name                  actor (function)     okSafe argNames
    //  --------------------- --------------------- -------------------- ------ --------
    { "masternode",          "masternode",         &masternode,         true,  {} },
    { "masternode",          "protx",              &protx,              true,  {} },
};

void RegisterMasternodeRPCCommands(CRPCTable& t)
{
    for (unsigned int i = 0; i < ARRAYLEN(commands); i++) {
        t.appendCommand(commands[i].name, &commands[i]);
    }
}

