// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MYNTA_EVO_PROVIDERTX_H
#define MYNTA_EVO_PROVIDERTX_H

#include "primitives/transaction.h"
#include "consensus/validation.h"
#include "netaddress.h"
#include "pubkey.h"
#include "serialize.h"
#include "uint256.h"

#include <vector>
#include <string>

// Forward declarations
class CBlock;
class CBlockIndex;

/**
 * Special transaction types for deterministic masternodes
 * Based on Dash DIP-0002 / DIP-0003
 */

// Transaction type identifiers
enum class TxType : uint16_t {
    TRANSACTION_NORMAL = 0,
    TRANSACTION_PROVIDER_REGISTER = 1,
    TRANSACTION_PROVIDER_UPDATE_SERVICE = 2,
    TRANSACTION_PROVIDER_UPDATE_REGISTRAR = 3,
    TRANSACTION_PROVIDER_UPDATE_REVOKE = 4,
};

// Convert transaction type to string
std::string TxTypeToString(TxType type);

// Check if transaction has special type
bool IsTxTypeSpecial(const CTransaction& tx);

// Get special transaction type
TxType GetTxType(const CTransaction& tx);

/**
 * CProRegTx - Provider Registration Transaction
 * 
 * Registers a new masternode on the network.
 */
class CProRegTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

    uint16_t nVersion{CURRENT_VERSION};
    uint16_t nType{0};                      // 0 = regular MN
    uint16_t nMode{0};                      // 0 = full MN
    COutPoint collateralOutpoint;           // Collateral UTXO
    CService addr;                          // IP address and port
    CKeyID keyIDOwner;                      // Owner key ID (P2PKH)
    std::vector<unsigned char> vchOperatorPubKey; // Operator BLS public key (48 bytes)
    CKeyID keyIDVoting;                     // Voting key ID
    uint16_t nOperatorReward{0};            // Operator reward (0-10000 = 0-100%)
    CScript scriptPayout;                   // Payout address
    uint256 inputsHash;                     // Hash of all inputs (replay protection)
    std::vector<unsigned char> vchSig;      // Signature by owner key

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(nType);
        READWRITE(nMode);
        READWRITE(collateralOutpoint);
        READWRITE(addr);
        READWRITE(keyIDOwner);
        READWRITE(vchOperatorPubKey);
        READWRITE(keyIDVoting);
        READWRITE(nOperatorReward);
        READWRITE(scriptPayout);
        READWRITE(inputsHash);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
    }

    std::string ToString() const;

    // Calculate the hash for signing
    uint256 GetSignatureHash() const;
    
    // Verify the payload signature
    bool CheckSignature(const CKeyID& keyID) const;
};

/**
 * CProUpServTx - Provider Update Service Transaction
 * 
 * Updates the IP address and/or port of a masternode.
 * Signed by the operator key.
 */
class CProUpServTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

    uint16_t nVersion{CURRENT_VERSION};
    uint256 proTxHash;                      // ProRegTx hash
    CService addr;                          // New IP address and port
    CScript scriptOperatorPayout;           // Optional operator payout address
    uint256 inputsHash;                     // Hash of all inputs
    std::vector<unsigned char> vchSig;      // BLS signature by operator key

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(proTxHash);
        READWRITE(addr);
        READWRITE(scriptOperatorPayout);
        READWRITE(inputsHash);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
    }

    std::string ToString() const;
    uint256 GetSignatureHash() const;
};

/**
 * CProUpRegTx - Provider Update Registrar Transaction
 * 
 * Updates the operator key, voting key, or payout address.
 * Signed by the owner key.
 */
class CProUpRegTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

    uint16_t nVersion{CURRENT_VERSION};
    uint256 proTxHash;                      // ProRegTx hash
    uint16_t nMode{0};                      // 0 = regular MN
    std::vector<unsigned char> vchOperatorPubKey; // New operator BLS key
    CKeyID keyIDVoting;                     // New voting key
    CScript scriptPayout;                   // New payout address
    uint256 inputsHash;                     // Hash of all inputs
    std::vector<unsigned char> vchSig;      // Signature by owner key

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(proTxHash);
        READWRITE(nMode);
        READWRITE(vchOperatorPubKey);
        READWRITE(keyIDVoting);
        READWRITE(scriptPayout);
        READWRITE(inputsHash);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
    }

    std::string ToString() const;
    uint256 GetSignatureHash() const;
    bool CheckSignature(const CKeyID& keyID) const;
};

/**
 * CProUpRevTx - Provider Update Revocation Transaction
 * 
 * Revokes a masternode registration.
 * Signed by the operator key.
 */
class CProUpRevTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

    // Revocation reasons
    enum RevocationReason : uint16_t {
        REASON_NOT_SPECIFIED = 0,
        REASON_TERMINATION = 1,
        REASON_COMPROMISED = 2,
        REASON_CHANGE_OF_KEYS = 3,
    };

    uint16_t nVersion{CURRENT_VERSION};
    uint256 proTxHash;                      // ProRegTx hash
    uint16_t nReason{REASON_NOT_SPECIFIED}; // Revocation reason
    uint256 inputsHash;                     // Hash of all inputs
    std::vector<unsigned char> vchSig;      // BLS signature by operator key

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(proTxHash);
        READWRITE(nReason);
        READWRITE(inputsHash);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
    }

    std::string ToString() const;
    uint256 GetSignatureHash() const;
};

// Validation functions
bool CheckProRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckProUpServTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckProUpRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckProUpRevTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);

// Master validation dispatcher
bool CheckSpecialTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);

// Process special transactions during block connection
bool ProcessSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, CValidationState& state, bool fJustCheck);

// Undo special transactions during block disconnection
bool UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex);

#endif // MYNTA_EVO_PROVIDERTX_H

