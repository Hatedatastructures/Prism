/**
 * @file RealityCertificateTest.cpp
 * @brief Reality 伪证书 DER 与 HMAC 签名回归测试。
 */

#include <Prism/Foundation/Utility/Crypto/Hkdf.hpp>
#include <Prism/Protocols/Reality/Detail/Handshake.hpp>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <array>
#include <cstring>
#include <memory>
#include <span>

#include <gtest/gtest.h>

TEST(RealityCertificate, UsesEd25519AndAuthKeyHmac)
{
    std::array<std::uint8_t, 32> AuthKey{};
    for (std::size_t Index = 0; Index < AuthKey.size(); ++Index)
    {
        AuthKey[Index] = static_cast<std::uint8_t>(Index + 1);
    }

    const auto [Der, Keypair] = Prism::Reality::Detail::Response::ResponseDetail::GenerateCertificate(AuthKey);
    ASSERT_FALSE(Der.empty());

    const auto *Cursor = Der.data();
    std::unique_ptr<X509, decltype(&X509_free)> Certificate(
        d2i_X509(nullptr, &Cursor, static_cast<long>(Der.size())), X509_free);
    ASSERT_TRUE(Certificate);

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> PublicKey(
        X509_get_pubkey(Certificate.get()), EVP_PKEY_free);
    ASSERT_TRUE(PublicKey);
    EXPECT_EQ(EVP_PKEY_id(PublicKey.get()), EVP_PKEY_ED25519);

    std::array<std::uint8_t, 32> EncodedPublicKey{};
    size_t PublicKeyLength = EncodedPublicKey.size();
    ASSERT_EQ(EVP_PKEY_get_raw_public_key(
                  PublicKey.get(), EncodedPublicKey.data(), &PublicKeyLength), 1);
    ASSERT_EQ(PublicKeyLength, EncodedPublicKey.size());
    EXPECT_EQ(EncodedPublicKey, Keypair.PublicKey);

    const ASN1_BIT_STRING *Signature = nullptr;
    const X509_ALGOR *Algorithm = nullptr;
    X509_get0_signature(&Signature, &Algorithm, Certificate.get());
    ASSERT_NE(Signature, nullptr);
    ASSERT_NE(Algorithm, nullptr);
    EXPECT_EQ(OBJ_obj2nid(Algorithm->algorithm), NID_ED25519);
    ASSERT_EQ(Signature->length, 64);

    const auto Expected = Prism::Crypto::HmacSha512(AuthKey, EncodedPublicKey);
    ASSERT_TRUE(Expected);
    EXPECT_EQ(std::memcmp(Signature->data, Expected->data(), Expected->size()), 0);
}
