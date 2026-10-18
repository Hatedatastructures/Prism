/**
 * @file RealityResponseTest.cpp
 * @brief Reality 完整服务端握手响应验证测试。
 */

#include <Prism/Protocols/Reality/Detail/Handshake.hpp>

#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

namespace
{

    using Bytes = std::vector<std::uint8_t>;

    struct MessageView final
    {
        std::size_t Header{0};
        std::size_t Body{0};
        std::size_t End{0};
    };

    auto FindMessage(const Bytes &Plaintext, const std::uint8_t Type)
        -> std::optional<MessageView>
    {
        std::size_t Offset = 0;
        while (Offset + 4 <= Plaintext.size())
        {
            const auto Length = static_cast<std::size_t>(Plaintext[Offset + 1]) << 16 |
                                  static_cast<std::size_t>(Plaintext[Offset + 2]) << 8 |
                                  Plaintext[Offset + 3];
            const MessageView View{Offset, Offset + 4, Offset + 4 + Length};
            if (View.End > Plaintext.size())
            {
                return std::nullopt;
            }
            if (Plaintext[Offset] == Type)
            {
                return View;
            }
            Offset = View.End;
        }
        return std::nullopt;
    }

} // namespace

TEST(RealityResponse, VerifiesCertificateVerifyAndServerFinished)
{
    std::array<std::uint8_t, 32> AuthKey{};
    for (std::size_t Index = 0; Index < AuthKey.size(); ++Index)
    {
        AuthKey[Index] = static_cast<std::uint8_t>(0x40 + Index);
    }

    Prism::Reality::Detail::Tls13Keys Keys;
    for (std::size_t Index = 0; Index < Keys.ServerHandshakeKey.size(); ++Index)
    {
        Keys.ServerHandshakeKey[Index] = static_cast<std::uint8_t>(Index + 1);
        Keys.ServerFinishedKey[Index] = static_cast<std::uint8_t>(0x80 + Index);
    }
    for (std::size_t Index = 0; Index < Keys.ServerHandshakeIv.size(); ++Index)
    {
        Keys.ServerHandshakeIv[Index] = static_cast<std::uint8_t>(0x20 + Index);
    }

    const Bytes ClientHello{0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0xAA, 0xBB};
    const Bytes ServerHello{0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0xCC, 0xDD};
    const auto Response = Prism::Reality::Detail::Response::BuildServerHandshake(
        Prism::Reality::Detail::Response::HandshakeRequest{AuthKey, Keys, ClientHello, ServerHello});
    ASSERT_TRUE(Response);

    const auto [DecryptError, Plaintext] = Prism::Reality::Detail::DecryptTlsRecord(
        Prism::Reality::Detail::Tls13RecordOpenInput{
            Response->Record, Keys.ServerHandshakeKey,
            std::span<const std::uint8_t, 12>(Keys.ServerHandshakeIv), 0});
    ASSERT_EQ(DecryptError, Prism::Error::None);
    ASSERT_EQ(Plaintext.ContentType, 0x16);

    const auto CertificateView = FindMessage(Plaintext.Data, 0x0B);
    const auto CertificateVerifyView = FindMessage(Plaintext.Data, 0x0F);
    const auto FinishedView = FindMessage(Plaintext.Data, 0x14);
    ASSERT_TRUE(CertificateView);
    ASSERT_TRUE(CertificateVerifyView);
    ASSERT_TRUE(FinishedView);

    const auto &Wire = Plaintext.Data;
    const auto CertificateBody = std::span<const std::uint8_t>(
        Wire.data() + CertificateView->Body, CertificateView->End - CertificateView->Body);
    ASSERT_GE(CertificateBody.size(), std::size_t{7});
    const auto CertificateLength = static_cast<std::size_t>(CertificateBody[4]) << 16 |
                                   static_cast<std::size_t>(CertificateBody[5]) << 8 |
                                   CertificateBody[6];
    ASSERT_LE(std::size_t{7} + CertificateLength, CertificateBody.size());
    const auto *CertificateCursor = CertificateBody.data() + 7;
    std::unique_ptr<X509, decltype(&X509_free)> Certificate(
        d2i_X509(nullptr, &CertificateCursor, static_cast<long>(CertificateLength)), X509_free);
    ASSERT_TRUE(Certificate);

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> PublicKey(
        X509_get_pubkey(Certificate.get()), EVP_PKEY_free);
    ASSERT_TRUE(PublicKey);
    std::array<std::uint8_t, 32> PublicBytes{};
    size_t PublicLength = PublicBytes.size();
    ASSERT_EQ(EVP_PKEY_get_raw_public_key(PublicKey.get(), PublicBytes.data(), &PublicLength), 1);
    ASSERT_EQ(PublicLength, PublicBytes.size());

    const auto BeforeCertificateVerify = std::span<const std::uint8_t>(
        Wire.data(), CertificateVerifyView->Header);
    const auto CertificateVerifyTranscript = std::array<std::span<const std::uint8_t>, 3>{
        ClientHello, ServerHello, BeforeCertificateVerify};
    const auto CertificateVerifyHash = Prism::Reality::Detail::HashTranscript(
        CertificateVerifyTranscript);
    ASSERT_TRUE(CertificateVerifyHash);
    const auto VerifyBody = std::span<const std::uint8_t>(
        Wire.data() + CertificateVerifyView->Body,
        CertificateVerifyView->End - CertificateVerifyView->Body);
    ASSERT_EQ(VerifyBody.size(), std::size_t{68});
    ASSERT_EQ(VerifyBody[0], 0x08);
    ASSERT_EQ(VerifyBody[1], 0x07);
    ASSERT_EQ(VerifyBody[2], 0x00);
    ASSERT_EQ(VerifyBody[3], 0x40);
    Bytes Signed(64, 0x20);
    constexpr std::string_view Context = "TLS 1.3, server CertificateVerify";
    Signed.insert(Signed.end(), Context.begin(), Context.end());
    Signed.push_back(0);
    Signed.insert(Signed.end(), CertificateVerifyHash->begin(), CertificateVerifyHash->end());
    EXPECT_EQ(ED25519_verify(Signed.data(), Signed.size(), VerifyBody.data() + 4, PublicBytes.data()), 1);

    const auto BeforeFinished = std::span<const std::uint8_t>(Wire.data(), FinishedView->Header);
    const auto FinishedTranscript = std::array<std::span<const std::uint8_t>, 3>{
        ClientHello, ServerHello, BeforeFinished};
    const auto FinishedHash = Prism::Reality::Detail::HashTranscript(FinishedTranscript);
    ASSERT_TRUE(FinishedHash);
    const auto ExpectedFinished = Prism::Reality::Detail::ComputeFinished(
        Keys.ServerFinishedKey, *FinishedHash);
    ASSERT_TRUE(ExpectedFinished);
    const auto FinishedBody = std::span<const std::uint8_t>(
        Wire.data() + FinishedView->Body, FinishedView->End - FinishedView->Body);
    ASSERT_EQ(FinishedBody.size(), ExpectedFinished->size());
    EXPECT_EQ(std::memcmp(FinishedBody.data(), ExpectedFinished->data(), ExpectedFinished->size()), 0);
}
