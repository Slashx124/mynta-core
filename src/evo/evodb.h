// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MYNTA_EVO_EVODB_H
#define MYNTA_EVO_EVODB_H

#include "dbwrapper.h"
#include "sync.h"
#include "uint256.h"

#include <memory>

/**
 * CEvoDB - Evolution database for deterministic masternode state
 * 
 * This database stores the state of the deterministic masternode list
 * in a way that allows for efficient queries and rollbacks during reorgs.
 */
class CEvoDB
{
private:
    mutable CCriticalSection cs;
    CDBWrapper db;

    // Current active transaction for atomic operations
    std::unique_ptr<CDBBatch> curDBTransaction;
    
    // Track if we're in the middle of a transaction
    bool hasTransaction{false};

public:
    explicit CEvoDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
    ~CEvoDB() = default;

    // Prevent copying
    CEvoDB(const CEvoDB&) = delete;
    CEvoDB& operator=(const CEvoDB&) = delete;

    // Transaction management
    void BeginTransaction();
    void CommitTransaction();
    void RollbackTransaction();
    bool HasTransaction() const { return hasTransaction; }

    // Template methods for reading/writing
    template <typename K, typename V>
    bool Read(const K& key, V& value) const
    {
        LOCK(cs);
        return db.Read(key, value);
    }

    template <typename K, typename V>
    void Write(const K& key, const V& value)
    {
        LOCK(cs);
        if (curDBTransaction) {
            curDBTransaction->Write(key, value);
        } else {
            db.Write(key, value);
        }
    }

    template <typename K>
    bool Exists(const K& key) const
    {
        LOCK(cs);
        return db.Exists(key);
    }

    template <typename K>
    void Erase(const K& key)
    {
        LOCK(cs);
        if (curDBTransaction) {
            curDBTransaction->Erase(key);
        } else {
            db.Erase(key);
        }
    }

    // Direct wrapper access for iteration
    CDBWrapper& GetRawDB() { return db; }
    const CDBWrapper& GetRawDB() const { return db; }

    // Sync to disk
    bool Sync();
};

// Global evolution database instance
extern std::unique_ptr<CEvoDB> evoDb;

#endif // MYNTA_EVO_EVODB_H

