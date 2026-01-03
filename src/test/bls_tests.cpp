// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_mynta.h"

#include "bls/bls.h"
#include "hash.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bls_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bls_key_generation)
{
    CBLSSecretKey sk;
    BOOST_CHECK(!sk.IsValid());
    
    sk.MakeNewKey();
    BOOST_CHECK(sk.IsValid());
    
    CBLSPublicKey pk = sk.GetPublicKey();
    BOOST_CHECK(pk.IsValid());
    
    // Public key should be 48 bytes
    std::vector<uint8_t> pkBytes = pk.ToBytes();
    BOOST_CHECK_EQUAL(pkBytes.size(), BLS_PUBLIC_KEY_SIZE);
}

BOOST_AUTO_TEST_CASE(bls_signing_verification)
{
    CBLSSecretKey sk;
    sk.MakeNewKey();
    BOOST_CHECK(sk.IsValid());
    
    CBLSPublicKey pk = sk.GetPublicKey();
    BOOST_CHECK(pk.IsValid());
    
    // Create a message hash
    uint256 msgHash = Hash(std::string("test message").begin(), std::string("test message").end());
    
    // Sign the message
    CBLSSignature sig = sk.Sign(msgHash);
    BOOST_CHECK(sig.IsValid());
    
    // Signature should be 96 bytes
    std::vector<uint8_t> sigBytes = sig.ToBytes();
    BOOST_CHECK_EQUAL(sigBytes.size(), BLS_SIGNATURE_SIZE);
    
    // Verify the signature
    BOOST_CHECK(sig.VerifyInsecure(pk, msgHash));
    
    // Wrong message should fail
    uint256 wrongHash = Hash(std::string("wrong message").begin(), std::string("wrong message").end());
    BOOST_CHECK(!sig.VerifyInsecure(pk, wrongHash));
}

BOOST_AUTO_TEST_CASE(bls_wrong_key_rejection)
{
    CBLSSecretKey sk1, sk2;
    sk1.MakeNewKey();
    sk2.MakeNewKey();
    
    CBLSPublicKey pk1 = sk1.GetPublicKey();
    CBLSPublicKey pk2 = sk2.GetPublicKey();
    
    uint256 msgHash = Hash(std::string("test").begin(), std::string("test").end());
    CBLSSignature sig = sk1.Sign(msgHash);
    
    // Signature should verify with pk1 but NOT with pk2
    BOOST_CHECK(sig.VerifyInsecure(pk1, msgHash));
    BOOST_CHECK(!sig.VerifyInsecure(pk2, msgHash));
}

BOOST_AUTO_TEST_CASE(bls_signature_aggregation)
{
    const size_t numKeys = 5;
    std::vector<CBLSPublicKey> pks;
    std::vector<CBLSSignature> sigs;
    
    uint256 msgHash = Hash(std::string("aggregate test").begin(), std::string("aggregate test").end());
    
    for (size_t i = 0; i < numKeys; i++) {
        CBLSSecretKey sk;
        sk.MakeNewKey();
        pks.push_back(sk.GetPublicKey());
        sigs.push_back(sk.Sign(msgHash));
        
        // Each individual signature should verify
        BOOST_CHECK(sigs[i].VerifyInsecure(pks[i], msgHash));
    }
    
    // Aggregate signatures
    CBLSSignature aggSig = CBLSSignature::AggregateSignatures(sigs);
    BOOST_CHECK(aggSig.IsValid());
    
    // Aggregated signature should verify against all public keys for same message
    BOOST_CHECK(aggSig.VerifySameMessage(pks, msgHash));
}

BOOST_AUTO_TEST_CASE(bls_public_key_aggregation)
{
    const size_t numKeys = 3;
    std::vector<CBLSPublicKey> pks;
    
    for (size_t i = 0; i < numKeys; i++) {
        CBLSSecretKey sk;
        sk.MakeNewKey();
        pks.push_back(sk.GetPublicKey());
    }
    
    // Aggregate public keys
    CBLSPublicKey aggPk = CBLSPublicKey::AggregatePublicKeys(pks);
    BOOST_CHECK(aggPk.IsValid());
}

BOOST_AUTO_TEST_CASE(bls_invalid_signature_rejection)
{
    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();
    
    uint256 msgHash = Hash(std::string("test").begin(), std::string("test").end());
    
    // Create an invalid signature (all zeros)
    CBLSSignature invalidSig;
    BOOST_CHECK(!invalidSig.IsValid());
    BOOST_CHECK(!invalidSig.VerifyInsecure(pk, msgHash));
}

BOOST_AUTO_TEST_CASE(bls_public_key_serialization)
{
    CBLSSecretKey sk;
    sk.MakeNewKey();
    CBLSPublicKey pk = sk.GetPublicKey();
    
    // Serialize
    std::vector<uint8_t> bytes = pk.ToBytes();
    BOOST_CHECK_EQUAL(bytes.size(), BLS_PUBLIC_KEY_SIZE);
    
    // Deserialize
    CBLSPublicKey pk2;
    BOOST_CHECK(pk2.SetBytes(bytes));
    BOOST_CHECK(pk2.IsValid());
    
    // Should be equal
    BOOST_CHECK(pk == pk2);
}

BOOST_AUTO_TEST_CASE(bls_signature_serialization)
{
    CBLSSecretKey sk;
    sk.MakeNewKey();
    
    uint256 msgHash = Hash(std::string("serialize test").begin(), std::string("serialize test").end());
    CBLSSignature sig = sk.Sign(msgHash);
    
    // Serialize
    std::vector<uint8_t> bytes = sig.ToBytes();
    BOOST_CHECK_EQUAL(bytes.size(), BLS_SIGNATURE_SIZE);
    
    // Deserialize
    CBLSSignature sig2;
    BOOST_CHECK(sig2.SetBytes(bytes));
    BOOST_CHECK(sig2.IsValid());
    
    // Should be equal
    BOOST_CHECK(sig == sig2);
}

BOOST_AUTO_TEST_CASE(bls_deterministic_key_from_seed)
{
    uint256 seed = Hash(std::string("deterministic seed").begin(), std::string("deterministic seed").end());
    
    CBLSSecretKey sk1;
    BOOST_CHECK(sk1.SetSecretKeyFromSeed(seed));
    BOOST_CHECK(sk1.IsValid());
    
    CBLSSecretKey sk2;
    BOOST_CHECK(sk2.SetSecretKeyFromSeed(seed));
    BOOST_CHECK(sk2.IsValid());
    
    // Same seed should produce same public key
    CBLSPublicKey pk1 = sk1.GetPublicKey();
    CBLSPublicKey pk2 = sk2.GetPublicKey();
    BOOST_CHECK(pk1 == pk2);
}

BOOST_AUTO_TEST_SUITE_END()
