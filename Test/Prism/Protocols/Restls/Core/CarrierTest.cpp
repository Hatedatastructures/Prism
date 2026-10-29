/**
 * @file CarrierTest.cpp
 * @brief Restls carrier 的真实 wire、计数器与内层传输 handoff 测试。
 */

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Restls/Detail/Codec.hpp>
#include <Prism/Protocols/Restls/Detail/Conn.hpp>
#include <Prism/Protocols/Restls/Detail/Retirement.hpp>
#include <Prism/Protocols/Restls/Restls.hpp>
#include <Prism/Protocols/Restls/Types.hpp>
#include <Prism/Transport/MemoryStream.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{

    namespace Net = boost::asio;
    namespace Restls = Prism::Restls;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;

    auto RetireAndVerify(Prism::SharedTransmission Transport) -> Net::awaitable<void>
    {
        const auto Result = co_await Restls::Detail::TransportRetirement::RetireAndDrain(
            std::move(Transport));
        EXPECT_TRUE(Result);
    }

    auto RunCoro(Net::io_context &Context, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Context, std::move(Operation),
                      [&Failure](std::exception_ptr Exception)
                      { Failure = std::move(Exception); });
        Context.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    auto MakeRandom() -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> Value{};
        for (std::size_t Index = 0; Index < Value.size(); ++Index)
        {
            Value[Index] = static_cast<std::uint8_t>(0x70U + Index);
        }
        return Value;
    }

    auto MakeTlsRecord(std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Record(Restls::TlsHdrlen + Payload.size());
        Record[0] = Restls::TlsApplicationData;
        Record[1] = 0x03U;
        Record[2] = 0x03U;
        Record[3] = static_cast<std::uint8_t>(Payload.size() >> 8U);
        Record[4] = static_cast<std::uint8_t>(Payload.size());
        std::copy(Payload.begin(), Payload.end(), Record.begin() + Restls::TlsHdrlen);
        return Record;
    }

    auto ReadExact(const Prism::SharedTransmission &Transport,
                   std::span<std::byte> Buffer) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            std::error_code ErrorCode;
            const auto ReadResult = co_await Transport->ReadSome(Buffer.subspan(Offset));
            ErrorCode = Prism::Fault::ToNative(ReadResult.Failure);
            const auto Read = ReadResult.Bytes;
            if (ErrorCode || Read == 0 || Read > Buffer.size() - Offset)
            {
                co_return false;
            }
            Offset += Read;
        }
        co_return true;
    }

    struct RestlsAcceptRequest final
    {
        Prism::SharedTransmission ServerTransport;
        Prism::SharedTransmission ClientTransport;
        std::string Password;
        std::array<std::uint8_t, 32> ServerRandom;
        std::vector<std::uint8_t> ClientFinished;
        std::vector<std::uint8_t> FirstEncrypted;
        std::shared_ptr<Restls::Detail::Conn<>> &Connection;
        std::vector<std::uint8_t> &ReceivedFirst;
    };

    auto RunRestlsAcceptScenario(RestlsAcceptRequest Request) -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Restls::Detail::Conn<>>(
            Request.ServerTransport, std::move(Request.Password));
        const auto Handshake = co_await Connection->ReadHandshake(
            Request.ServerRandom, Request.ClientFinished);
        if (!Handshake)
        {
            EXPECT_TRUE(Handshake);
            co_await RetireAndVerify(Connection);
            co_await RetireAndVerify(Request.ClientTransport);
            co_return;
        }

        const auto Protected = Restls::Detail::ProtectFirstEncrypted(
            Request.FirstEncrypted, Connection->Secret(), Request.ServerRandom);
        if (Protected.first != Error::None)
        {
            EXPECT_EQ(Protected.first, Error::None);
            co_await RetireAndVerify(Connection);
            co_await RetireAndVerify(Request.ClientTransport);
            co_return;
        }
        const auto ProtectedBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Protected.second.data()),
            Protected.second.size());
        const auto Write = co_await Request.ServerTransport->WriteExact(ProtectedBytes);
        if (Write.Failure.Failed())
        {
            EXPECT_FALSE(Write.Failure.Failed());
            co_await RetireAndVerify(Connection);
            co_await RetireAndVerify(Request.ClientTransport);
            co_return;
        }
        EXPECT_EQ(Write.Bytes, Protected.second.size());

        const auto Received = co_await ReadExact(
            Request.ClientTransport,
            std::span<std::byte>(reinterpret_cast<std::byte *>(Request.ReceivedFirst.data()),
                                 Request.ReceivedFirst.size()));
        EXPECT_TRUE(Received);
        Request.Connection = std::move(Connection);
    }

    struct RestlsWriteRequest final
    {
        std::shared_ptr<Restls::Detail::Conn<>> Client;
        Prism::SharedTransmission ServerTransport;
        std::array<std::uint8_t, 32> ServerRandom;
        std::vector<std::uint8_t> ClientFinished;
        std::vector<std::uint8_t> FirstData;
        std::vector<std::uint8_t> SecondData;
    };

    auto RunRestlsWriteScenario(RestlsWriteRequest Request) -> Net::awaitable<void>
    {
        const auto Handshake = co_await Request.Client->WriteHandshake(
            Request.ServerRandom, Request.ClientFinished);
        EXPECT_TRUE(Handshake);
        std::error_code ErrorCode;
        const auto FirstWrite = co_await Request.Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.FirstData.data()),
                                       Request.FirstData.size()));
        ErrorCode = Prism::Fault::ToNative(FirstWrite.Failure);
        const auto FirstWritten = FirstWrite.Bytes;
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(FirstWritten, Request.FirstData.size());

        const auto Secret = Restls::Detail::DeriveSecret("restls-counter-password");
        const auto FirstExpected = Restls::Detail::BuildFrame(Restls::Detail::FrameOptions{
            .Secret = Secret,
            .ServerRandom = Request.ServerRandom,
            .Direction = Restls::FlowDirection::ToServer,
            .Counter = 0,
            .ClientFinished = Request.ClientFinished,
            .Data = Request.FirstData,
            .PaddingLength = 0,
            .Command = Restls::CmdTypeNoop,
            .CommandArgument = 0});
        EXPECT_EQ(FirstExpected.first, Error::None);
        if (FirstExpected.first != Error::None)
        {
            co_await RetireAndVerify(Request.ServerTransport);
            co_await RetireAndVerify(Request.Client);
            co_return;
        }
        std::vector<std::byte> FirstWire(FirstExpected.second.size());
        EXPECT_TRUE(co_await ReadExact(Request.ServerTransport, FirstWire));
        EXPECT_EQ(std::vector<std::uint8_t>(
                      reinterpret_cast<const std::uint8_t *>(FirstWire.data()),
                      reinterpret_cast<const std::uint8_t *>(FirstWire.data()) + FirstWire.size()),
                  FirstExpected.second);

        const auto SecondWrite = co_await Request.Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.SecondData.data()),
                                       Request.SecondData.size()));
        ErrorCode = Prism::Fault::ToNative(SecondWrite.Failure);
        const auto SecondWritten = SecondWrite.Bytes;
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(SecondWritten, Request.SecondData.size());
        const auto SecondExpected = Restls::Detail::BuildFrame(Restls::Detail::FrameOptions{
            .Secret = Secret,
            .ServerRandom = Request.ServerRandom,
            .Direction = Restls::FlowDirection::ToServer,
            .Counter = 1,
            .ClientFinished = {},
            .Data = Request.SecondData,
            .PaddingLength = 0,
            .Command = Restls::CmdTypeNoop,
            .CommandArgument = 0});
        EXPECT_EQ(SecondExpected.first, Error::None);
        if (SecondExpected.first != Error::None)
        {
            co_await RetireAndVerify(Request.ServerTransport);
            co_await RetireAndVerify(Request.Client);
            co_return;
        }
        std::vector<std::byte> SecondWire(SecondExpected.second.size());
        EXPECT_TRUE(co_await ReadExact(Request.ServerTransport, SecondWire));
        EXPECT_EQ(std::vector<std::uint8_t>(
                      reinterpret_cast<const std::uint8_t *>(SecondWire.data()),
                      reinterpret_cast<const std::uint8_t *>(SecondWire.data()) + SecondWire.size()),
                  SecondExpected.second);
        co_await RetireAndVerify(Request.ServerTransport);
        co_await RetireAndVerify(Request.Client);
    }

    struct RestlsReplayRequest final
    {
        std::shared_ptr<Restls::Detail::Conn<>> Server;
        Prism::SharedTransmission ClientTransport;
        std::array<std::uint8_t, 32> ServerRandom;
        std::vector<std::uint8_t> ClientFinished;
        std::vector<std::uint8_t> FirstFrame;
        std::vector<std::uint8_t> SecondFrame;
    };

    auto RunRestlsReplayScenario(RestlsReplayRequest Request) -> Net::awaitable<void>
    {
        const auto Handshake = co_await Request.Server->ReadHandshake(
            Request.ServerRandom, Request.ClientFinished);
        EXPECT_TRUE(Handshake);
        std::error_code ErrorCode;
        const auto FirstWrite = co_await Request.ClientTransport->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.FirstFrame.data()),
                                       Request.FirstFrame.size()));
        ErrorCode = Prism::Fault::ToNative(FirstWrite.Failure);
        EXPECT_FALSE(ErrorCode);
        std::array<std::byte, 32> Buffer{};
        const auto FirstReadResult = co_await Request.Server->ReadSome(Buffer);
        ErrorCode = Prism::Fault::ToNative(FirstReadResult.Failure);
        const auto FirstRead = FirstReadResult.Bytes;
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(std::vector<std::uint8_t>(
                      reinterpret_cast<const std::uint8_t *>(Buffer.data()),
                      reinterpret_cast<const std::uint8_t *>(Buffer.data()) + FirstRead),
                  (std::vector<std::uint8_t>{'r', 'e', 'a', 'd'}));

        const auto SecondWrite = co_await Request.ClientTransport->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.SecondFrame.data()),
                                       Request.SecondFrame.size()));
        ErrorCode = Prism::Fault::ToNative(SecondWrite.Failure);
        EXPECT_FALSE(ErrorCode);
        const auto SecondReadResult = co_await Request.Server->ReadSome(Buffer);
        ErrorCode = Prism::Fault::ToNative(SecondReadResult.Failure);
        const auto SecondRead = SecondReadResult.Bytes;
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(SecondRead, 4U);

        const auto ThirdWrite = co_await Request.ClientTransport->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.FirstFrame.data()),
                                       Request.FirstFrame.size()));
        ErrorCode = Prism::Fault::ToNative(ThirdWrite.Failure);
        EXPECT_FALSE(ErrorCode);
        const auto ReplayReadResult = co_await Request.Server->ReadSome(Buffer);
        const auto ReplayRead = ReplayReadResult.Bytes;
        EXPECT_EQ(ReplayRead, 0U);
        EXPECT_EQ(ReplayReadResult.Failure.Code, Prism::Fault::Code::AuthFailed);
        EXPECT_FALSE(ReplayReadResult.Failure.Native);
        co_await RetireAndVerify(Request.Server);
        co_await RetireAndVerify(Request.ClientTransport);
    }

    TEST(RestlsCarrier, ProtectsFirstEncryptedFrameAndReturnsInnerOwner)
    {
        Net::io_context Context;
        auto [ServerMemory, ClientMemory] = MakeMemoryPair(Context.get_executor());
        auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
        const auto OriginalTransport = ServerTransport;
        const auto ServerRandom = MakeRandom();
        const std::vector<std::uint8_t> ClientFinished = MakeTlsRecord(
            std::array<std::uint8_t, 8>{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
        const std::vector<std::uint8_t> FirstEncrypted = MakeTlsRecord(
            std::array<std::uint8_t, 20>{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                         0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
                                         0xb0, 0xb1, 0xb2, 0xb3});
        std::shared_ptr<Restls::Detail::Conn<>> Connection;
        std::vector<std::uint8_t> ReceivedFirst(FirstEncrypted.size());
        RunCoro(Context, RunRestlsAcceptScenario(RestlsAcceptRequest{
            ServerTransport, ClientTransport, "restls-carrier-password", ServerRandom,
            ClientFinished, FirstEncrypted, Connection, ReceivedFirst}));

        ASSERT_TRUE(Connection);
        EXPECT_EQ(Connection->NextLayer(), OriginalTransport.get());

        auto ExpectedFirst = FirstEncrypted;
        const auto Secret = Restls::Detail::DeriveSecret("restls-carrier-password");
        const auto Mask = Restls::Detail::ComputeServerMask(Secret, ServerRandom);
        for (std::size_t Index = 0;
             Index < std::min(Restls::HsMaclen, ExpectedFirst.size() - Restls::TlsHdrlen);
             ++Index)
        {
            ExpectedFirst[Restls::TlsHdrlen + Index] ^= Mask[Index];
        }
        EXPECT_EQ(ReceivedFirst, ExpectedFirst);

        const auto Released = Connection->Release();
        EXPECT_EQ(Released, OriginalTransport);
        EXPECT_EQ(Connection->NextLayer(), nullptr);
    }

    TEST(RestlsCarrier, WritesFirstClientFrameWithFinishedAndAdvancesCounter)
    {
        Net::io_context Context;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(Context.get_executor());
        auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
        const auto ServerRandom = MakeRandom();
        const std::vector<std::uint8_t> ClientFinished = MakeTlsRecord(
            std::array<std::uint8_t, 8>{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28});
        const std::vector<std::uint8_t> FirstData{'f', 'i', 'r', 's', 't'};
        const std::vector<std::uint8_t> SecondData{'s', 'e', 'c', 'o', 'n', 'd'};
        auto Client = std::make_shared<Restls::Detail::Conn<>>(ClientTransport, "restls-counter-password");

        RunCoro(Context, RunRestlsWriteScenario(RestlsWriteRequest{
            Client, ServerTransport, ServerRandom, ClientFinished, FirstData, SecondData}));
    }

    TEST(RestlsCarrier, ReadsFinishedBoundFrameThenRejectsReplay)
    {
        Net::io_context Context;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(Context.get_executor());
        auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
        const auto ServerRandom = MakeRandom();
        const std::vector<std::uint8_t> ClientFinished = MakeTlsRecord(
            std::array<std::uint8_t, 8>{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38});
        const std::vector<std::uint8_t> Data{'r', 'e', 'a', 'd'};
        const auto Secret = Restls::Detail::DeriveSecret("restls-read-password");
        const auto FirstFrame = Restls::Detail::BuildFrame(Restls::Detail::FrameOptions{
            .Secret = Secret,
            .ServerRandom = ServerRandom,
            .Direction = Restls::FlowDirection::ToServer,
            .Counter = 0,
            .ClientFinished = ClientFinished,
            .Data = Data,
            .PaddingLength = 0,
            .Command = Restls::CmdTypeNoop,
            .CommandArgument = 0});
        ASSERT_EQ(FirstFrame.first, Error::None);
        const auto SecondFrame = Restls::Detail::BuildFrame(Restls::Detail::FrameOptions{
            .Secret = Secret,
            .ServerRandom = ServerRandom,
            .Direction = Restls::FlowDirection::ToServer,
            .Counter = 1,
            .ClientFinished = {},
            .Data = Data,
            .PaddingLength = 0,
            .Command = Restls::CmdTypeNoop,
            .CommandArgument = 0});
        ASSERT_EQ(SecondFrame.first, Error::None);
        auto Server = std::make_shared<Restls::Detail::Conn<>>(ServerTransport, "restls-read-password");

        RunCoro(Context, RunRestlsReplayScenario(RestlsReplayRequest{
            Server, ClientTransport, ServerRandom, ClientFinished, FirstFrame.second, SecondFrame.second}));
    }

} // namespace
