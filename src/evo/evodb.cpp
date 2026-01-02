// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "evo/evodb.h"
#include "util.h"

std::unique_ptr<CEvoDB> evoDb;

CEvoDB::CEvoDB(size_t nCacheSize, bool fMemory, bool fWipe)
    : db(GetDataDir() / "evodb", nCacheSize, fMemory, fWipe)
{
}

void CEvoDB::BeginTransaction()
{
    LOCK(cs);
    assert(!hasTransaction);
    curDBTransaction = std::make_unique<CDBBatch>(db);
    hasTransaction = true;
}

void CEvoDB::CommitTransaction()
{
    LOCK(cs);
    assert(hasTransaction);
    db.WriteBatch(*curDBTransaction);
    curDBTransaction.reset();
    hasTransaction = false;
}

void CEvoDB::RollbackTransaction()
{
    LOCK(cs);
    assert(hasTransaction);
    curDBTransaction.reset();
    hasTransaction = false;
}

bool CEvoDB::Sync()
{
    LOCK(cs);
    return db.Sync();
}

