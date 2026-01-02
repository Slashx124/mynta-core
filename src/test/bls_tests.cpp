// Copyright (c) 2026 The Mynta Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bls/bls.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bls_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bls_key_generation)
{
    // Test basic key generation
    bls::CBLSSecretKey sk;
    sk.MakeNewKey();
    BOOST_CHECK(sk.IsValid());
    
    // Generate public key from secret key
    bls::CBLSPublicKey pk = sk.GetPublicKey();
    BOOST_CHECK(pk.IsValid());
    
    // Keys should not be null
    BOOST_CHECK(!sk.IsNull());
    BOOST_CHECK(!pk.IsNull());
}

BOOST_AUTO_TEST_CASE(bls_signing_verification)
{
    // Generate key pair
    bls::CBLSSecretKey sk;
    sk.MakeNewKey();
    bls::CBLSPublicKey pk = sk.GetPublicKey();
    
    // Create a test message
    uint256 msgHash;
    msgHash.SetHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    
    // Sign the message
    bls::CBLSSignature sig = sk.Sign(msgHash);
    BOOST_CHECK(sig.IsValid());
    
    // Verify the signature
    BOOST_CHECK(sig.VerifyInsecure(pk, msgHash));
    
    // Verify with wrong message fails
    uint256 wrongHash;
    wrongHash.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    BOOST_CHECK(!sig.VerifyInsecure(pk, wrongHash));
}

BOOST_AUTO_TEST_CASE(bls_wrong_key_rejection)
{
    // Generate two different key pairs
    bls::CBLSSecretKey sk1, sk2;
    sk1.MakeNewKey();
    sk2.MakeNewKey();
    
    bls::CBLSPublicKey pk1 = sk1.GetPublicKey();
    bls::CBLSPublicKey pk2 = sk2.GetPublicKey();
    
    // Sign with key 1
    uint256 msgHash;
    msgHash.SetHex("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    bls::CBLSSignature sig = sk1.Sign(msgHash);
    
    // Signature should verify with pk1 but NOT with pk2
    BOOST_CHECK(sig.VerifyInsecure(pk1, msgHash));
    BOOST_CHECK(!sig.VerifyInsecure(pk2, msgHash));
}

BOOST_AUTO_TEST_CASE(bls_signature_aggregation)
{
    // Generate multiple keys
    const size_t numKeys = 5;
    std::vector<bls::CBLSSecretKey> sks(numKeys);
    std::vector<bls::CBLSPublicKey> pks(numKeys);
    std::vector<bls::CBLSSignature> sigs(numKeys);
    
    uint256 msgHash;
    msgHash.SetHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    
    for (size_t i = 0; i < numKeys; i++) {
        sks[i].MakeNewKey();
        pks[i] = sks[i].GetPublicKey();
        sigs[i] = sks[i].Sign(msgHash);
        
        // Each individual signature should verify
        BOOST_CHECK(sigs[i].VerifyInsecure(pks[i], msgHash));
    }
    
    // Aggregate signatures
    bls::CBLSSignature aggSig;
    aggSig.AggregateInsecure(sigs);
    BOOST_CHECK(aggSig.IsValid());
    
    // Aggregate public keys
    bls::CBLSPublicKey aggPk;
    aggPk.AggregateInsecure(pks);
    BOOST_CHECK(aggPk.IsValid());
    
    // Aggregated signature should verify against aggregated public key
    BOOST_CHECK(aggSig.VerifyInsecure(aggPk, msgHash));
}

BOOST_AUTO_TEST_CASE(bls_serialization)
{
    // Generate key pair
    bls::CBLSSecretKey sk;
    sk.MakeNewKey();
    bls::CBLSPublicKey pk = sk.GetPublicKey();
    
    // Sign a message
    uint256 msgHash;
    msgHash.SetHex("deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000");
    bls::CBLSSignature sig = sk.Sign(msgHash);
    
    // Serialize secret key
    CDataStream skStream(SER_NETWORK, PROTOCOL_VERSION);
    sk.Serialize(skStream);
    
    // Deserialize and compare
    bls::CBLSSecretKey sk2;
    sk2.Unserialize(skStream);
    BOOST_CHECK(sk == sk2);
    
    // Serialize public key
    CDataStream pkStream(SER_NETWORK, PROTOCOL_VERSION);
    pk.Serialize(pkStream);
    
    bls::CBLSPublicKey pk2;
    pk2.Unserialize(pkStream);
    BOOST_CHECK(pk == pk2);
    
    // Serialize signature
    CDataStream sigStream(SER_NETWORK, PROTOCOL_VERSION);
    sig.Serialize(sigStream);
    
    bls::CBLSSignature sig2;
    sig2.Unserialize(sigStream);
    BOOST_CHECK(sig == sig2);
    
    // Deserialized signature should still verify
    BOOST_CHECK(sig2.VerifyInsecure(pk, msgHash));
}

BOOST_AUTO_TEST_CASE(bls_invalid_signature_rejection)
{
    bls::CBLSSecretKey sk;
    sk.MakeNewKey();
    bls::CBLSPublicKey pk = sk.GetPublicKey();
    
    uint256 msgHash;
    msgHash.SetHex("cafe00000000000000000000000000000000000000000000000000000000cafe");
    
    // Create an invalid signature (all zeros)
    bls::CBLSSignature invalidSig;
    // Don't initialize - should be invalid
    BOOST_CHECK(!invalidSig.IsValid());
    BOOST_CHECK(!invalidSig.VerifyInsecure(pk, msgHash));
}

BOOST_AUTO_TEST_CASE(bls_null_key_handling)
{
    // Null keys should be marked as invalid
    bls::CBLSSecretKey nullSk;
    bls::CBLSPublicKey nullPk;
    bls::CBLSSignature nullSig;
    
    BOOST_CHECK(!nullSk.IsValid());
    BOOST_CHECK(!nullPk.IsValid());
    BOOST_CHECK(!nullSig.IsValid());
    
    // Operations with null keys should fail gracefully
    uint256 msgHash;
    msgHash.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    
    // Signing with null key should produce invalid signature
    bls::CBLSSignature sig = nullSk.Sign(msgHash);
    BOOST_CHECK(!sig.IsValid());
    
    // Verification with null key/sig should return false
    BOOST_CHECK(!nullSig.VerifyInsecure(nullPk, msgHash));
}

BOOST_AUTO_TEST_CASE(bls_deterministic_key_from_seed)
{
    // Same seed should produce same key
    std::vector<unsigned char> seed(32, 0x42);
    
    bls::CBLSSecretKey sk1;
    sk1.SetBuf(seed.data(), seed.size());
    
    bls::CBLSSecretKey sk2;
    sk2.SetBuf(seed.data(), seed.size());
    
    BOOST_CHECK(sk1 == sk2);
    BOOST_CHECK(sk1.GetPublicKey() == sk2.GetPublicKey());
    
    // Different seed should produce different key
    seed[0] = 0x43;
    bls::CBLSSecretKey sk3;
    sk3.SetBuf(seed.data(), seed.size());
    
    BOOST_CHECK(sk1 != sk3);
}

BOOST_AUTO_TEST_SUITE_END()

