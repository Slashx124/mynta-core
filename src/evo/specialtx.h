// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MYNTA_EVO_SPECIALTX_H
#define MYNTA_EVO_SPECIALTX_H

#include "primitives/transaction.h"
#include "streams.h"
#include "version.h"

#include <vector>

/**
 * Helper functions for working with special transaction payloads
 */

// Check if a transaction is a special transaction
inline bool IsSpecialTx(const CTransaction& tx)
{
    return tx.nVersion >= 3 && tx.nType != 0;
}

// Get the payload from a special transaction
template <typename T>
inline bool GetTxPayload(const std::vector<unsigned char>& vchExtraPayload, T& obj)
{
    try {
        CDataStream ds(vchExtraPayload, SER_NETWORK, PROTOCOL_VERSION);
        ds >> obj;
        return ds.empty();
    } catch (const std::exception& e) {
        return false;
    }
}

template <typename T>
inline bool GetTxPayload(const CMutableTransaction& tx, T& obj)
{
    return GetTxPayload(tx.vExtraPayload, obj);
}

template <typename T>
inline bool GetTxPayload(const CTransaction& tx, T& obj)
{
    return GetTxPayload(tx.vExtraPayload, obj);
}

// Set the payload of a special transaction
template <typename T>
inline void SetTxPayload(CMutableTransaction& tx, const T& obj)
{
    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds << obj;
    tx.vExtraPayload.assign(ds.begin(), ds.end());
}

// Calculate the hash of a special transaction (including payload)
uint256 CalcTxInputsHash(const CTransaction& tx);

#endif // MYNTA_EVO_SPECIALTX_H

