/**
 * @file SessionIdChannelErrorTest.cpp
 * @brief Reality SessionId 实验通道的认证与底层 I/O 错误边界。
 */

#include "../Session/IdSupport.hpp"
#include "SessionIdChannel.hpp"

#include <Prism/Protocols/Reality/Detail/KeyMaterial.hpp>
#include <Prism/Protocols/Reality/CarrierTypes.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Reality = Prism::Reality;
    namespace Experiment = Prism::Reality::Detail::Experiments;
    using Prism::Error;
    using Prism::SharedTransmission;
    using SessionIdChannel = Reality::Detail::SessionIdChannel<>;

    auto MakeKeyPair(std::array<std::uint8_t, Reality::KeyLen> &PrivateKey,
                     std::array<std::uint8_t, Reality::KeyLen> &PublicKey) -> void
    {
        EXPECT_FALSE(Reality::Detail::GenerateKeypair(PrivateKey, PublicKey));
    }

    auto MakeRandom(const std::uint8_t Seed, const std::size_t Length)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result(Length);
        for (std::size_t Index = 0; Index < Length; ++Index)
        {
            Result[Index] = static_cast<std::uint8_t>(Index * 7U + Seed);
        }
        return Result;
    }

    auto ExpectCloseTransmission(const SharedTransmission &Transport) -> Net::awaitable<void>
    {
        const auto Close = Transport->Close();
        const auto Drain = co_await Transport->Activity()->Drain();
        Prism::Testing::ExpectFixtureCloseReceipt({Close, Drain});
    }

    auto ExpectFullWrite(const Prism::IoResult &Result, const std::size_t ExpectedBytes) -> void
    {
        EXPECT_LE(Result.Bytes, ExpectedBytes);
        EXPECT_EQ(Result.Bytes, ExpectedBytes);
        EXPECT_TRUE(Result.Failure.Succeeded());
    }

    struct SealRequest final
    {
        std::span<const std::uint8_t> ClientPrivateKey;
        std::span<const std::uint8_t> ServerPublicKey;
        std::span<const std::uint8_t> ClientRandom;
        std::span<const std::uint8_t> Hello;
        std::span<const std::uint8_t, 8> ShortId;
        std::array<std::uint8_t, Reality::SessionIdAuthLen> &Sealed;
    };

    auto MakeSealedSessionId(SealRequest Request) -> bool
    {
        std::array<std::uint8_t, Reality::KeyLen> Shared{};
        if (Reality::Detail::X25519Shared(Request.ClientPrivateKey, Request.ServerPublicKey, Shared))
        {
            return true;
        }
        std::array<std::uint8_t, Reality::KeyLen> AuthKey{};
        if (Reality::Detail::DeriveAuthKey(Shared, Request.ClientRandom, AuthKey))
        {
            return true;
        }
        std::array<std::uint8_t, 16> Plaintext{};
        Plaintext[0] = 0x01;
        std::copy(Request.ShortId.begin(), Request.ShortId.end(), Plaintext.begin() + 8);
        return Reality::Detail::SealSessionId(
            Reality::Detail::SessionIdSealInput{AuthKey, Request.ClientRandom, Plaintext, Request.Hello},
            Request.Sealed);
    }

    auto RunReadEof(SharedTransmission Client, SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, Reality::KeyLen> PrivateKey{};
        std::array<std::uint8_t, Reality::KeyLen> PublicKey{};
        MakeKeyPair(PrivateKey, PublicKey);
        const auto ClientRandom = MakeRandom(0x55, 32);
        const auto Hello = MakeRandom(0x66, 96);
        const std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        auto Channel = std::make_shared<SessionIdChannel>(Server, PrivateKey);
        co_await ExpectCloseTransmission(Client);
        const Reality::Detail::HandshakeParams Params{ClientRandom, Hello, ShortId};
        std::array<std::uint8_t, Reality::MaxShortIdLen> OutputShortId{};
        const auto Result = co_await Channel->ReadHandshake(PublicKey, Params, OutputShortId);
        EXPECT_EQ(Result, Error::UnexpectedEof);
        co_await ExpectCloseTransmission(Channel);
    }

    auto RunBadAuth(SharedTransmission Client, SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, Reality::KeyLen> ClientPrivate{};
        std::array<std::uint8_t, Reality::KeyLen> ClientPublic{};
        std::array<std::uint8_t, Reality::KeyLen> ServerPrivate{};
        std::array<std::uint8_t, Reality::KeyLen> ServerPublic{};
        MakeKeyPair(ClientPrivate, ClientPublic);
        MakeKeyPair(ServerPrivate, ServerPublic);
        const auto ClientRandom = MakeRandom(0x55, 32);
        const auto Hello = MakeRandom(0x66, 96);
        const std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        std::array<std::uint8_t, Reality::SessionIdAuthLen> Sealed{};
        EXPECT_FALSE(MakeSealedSessionId(SealRequest{
            ClientPrivate, ServerPublic, ClientRandom, Hello, ShortId, Sealed}));
        Sealed[0] ^= 0xFF;
        const auto Write = co_await Client->WriteSome(Prism::AsBytes(
            std::span<const std::uint8_t>(Sealed)));
        ExpectFullWrite(Write, Sealed.size());
        auto Channel = std::make_shared<SessionIdChannel>(Server, ServerPrivate);
        const Reality::Detail::HandshakeParams Params{ClientRandom, Hello, ShortId};
        std::array<std::uint8_t, Reality::MaxShortIdLen> OutputShortId{};
        const auto Result = co_await Channel->ReadHandshake(ClientPublic, Params, OutputShortId);
        EXPECT_EQ(Result, Error::BadAuth);
        co_await ExpectCloseTransmission(Channel);
    }

    auto RunReadKdfError(SharedTransmission Client, SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, Reality::KeyLen> PrivateKey{};
        std::array<std::uint8_t, Reality::KeyLen> PublicKey{};
        MakeKeyPair(PrivateKey, PublicKey);
        const auto ClientRandom = MakeRandom(0x55, 32);
        const auto Hello = MakeRandom(0x66, 96);
        const std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};
        std::array<std::uint8_t, 32> Junk{};
        Junk.fill(0xAA);
        const auto Write = co_await Client->WriteSome(
            Prism::AsBytes(std::span<const std::uint8_t>(Junk)));
        ExpectFullWrite(Write, Junk.size());
        auto Channel = std::make_shared<SessionIdChannel>(Server, PrivateKey);
        const std::array<std::uint8_t, 16> BadPublicKey{};
        const Reality::Detail::HandshakeParams Params{ClientRandom, Hello, ShortId};
        std::array<std::uint8_t, Reality::MaxShortIdLen> OutputShortId{};
        const auto Result = co_await Channel->ReadHandshake(BadPublicKey, Params, OutputShortId);
        EXPECT_EQ(Result, Error::KdfError);
        co_await ExpectCloseTransmission(Channel);
    }

    auto RunWriteIoError(SharedTransmission Client, SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, Reality::KeyLen> ClientPrivateKey{};
        std::array<std::uint8_t, Reality::KeyLen> ClientPublicKey{};
        std::array<std::uint8_t, Reality::KeyLen> ServerPrivateKey{};
        std::array<std::uint8_t, Reality::KeyLen> ServerPublicKey{};
        MakeKeyPair(ClientPrivateKey, ClientPublicKey);
        MakeKeyPair(ServerPrivateKey, ServerPublicKey);
        const auto ClientRandom = MakeRandom(0x55, 32);
        const auto Hello = MakeRandom(0x66, 96);
        const std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};
        auto Channel = std::make_shared<SessionIdChannel>(Client, ClientPrivateKey);
        co_await ExpectCloseTransmission(Server);
        const Reality::Detail::HandshakeParams Params{ClientRandom, Hello, ShortId};
        const auto Result = co_await Channel->WriteHandshake(ServerPublicKey, Params);
        EXPECT_EQ(Result, Error::IoError);
        co_await ExpectCloseTransmission(Channel);
    }

    auto RunWriteKdfError(SharedTransmission Client, SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, Reality::KeyLen> PrivateKey{};
        std::array<std::uint8_t, Reality::KeyLen> PublicKey{};
        MakeKeyPair(PrivateKey, PublicKey);
        const auto ClientRandom = MakeRandom(0x55, 32);
        const auto Hello = MakeRandom(0x66, 96);
        const std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};
        auto Channel = std::make_shared<SessionIdChannel>(Client, PrivateKey);
        const std::array<std::uint8_t, 16> InvalidPublicKey{};
        const Reality::Detail::HandshakeParams Params{ClientRandom, Hello, ShortId};
        const auto Result = co_await Channel->WriteHandshake(InvalidPublicKey, Params);
        EXPECT_EQ(Result, Error::KdfError);
        co_await ExpectCloseTransmission(Channel);
        (void)Server;
    }

    auto RunNotOpenReadWrite(SharedTransmission Client, SharedTransmission Server)
        -> Net::awaitable<void>
    {
        auto Channel = std::make_shared<SessionIdChannel>(
            Client, std::array<std::uint8_t, Reality::KeyLen>{});
        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Channel->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Prism::Fault::ToNative(Read.Failure), Prism::make_error_code(Error::NotOpen));
        const auto Write = co_await Channel->WriteSome(std::span<const std::byte>(Buffer).first(4));
        EXPECT_EQ(Write.Bytes, 0U);
        EXPECT_EQ(Prism::Fault::ToNative(Write.Failure), Prism::make_error_code(Error::NotOpen));
        co_await ExpectCloseTransmission(Channel);
        (void)Server;
    }

    template <typename Scenario>
    auto RunScenario(Scenario Operation) -> void
    {
        Net::io_context Context;
        auto Pair = Experiment::TestSupport::MakePair(Context.get_executor());
        Experiment::TestSupport::RunAndClose(
            Context, Pair, Operation(Pair.FirstOwner, Pair.SecondOwner));
    }

    TEST(StealthRealityConnError, ReadHandshakeEof)
    {
        RunScenario(RunReadEof);
    }

    TEST(StealthRealityConnError, ReadHandshakeBadAuth)
    {
        RunScenario(RunBadAuth);
    }

    TEST(StealthRealityConnError, ReadHandshakeKdfError)
    {
        RunScenario(RunReadKdfError);
    }

    TEST(StealthRealityConnError, WriteHandshakeKdfError)
    {
        RunScenario(RunWriteKdfError);
    }

    TEST(StealthRealityConnError, WriteHandshakeIoError)
    {
        RunScenario(RunWriteIoError);
    }

    TEST(StealthRealityConnError, NotOpenReadWrite)
    {
        RunScenario(RunNotOpenReadWrite);
    }
}
