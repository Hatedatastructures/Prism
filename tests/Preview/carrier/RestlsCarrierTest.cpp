/**
 * @file RestlsCarrierTest.cpp
 * @brief Restls carrier 的真实 wire、计数器与内层传输 handoff 测试。
 */

#include <Preview/Composition/Carrier/FacadeCarrier.hpp>
#include <Preview/Protocols/Restls/Restls.hpp>
#include <Preview/Transport/MemoryStream.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace
{

    namespace Carrier = Preview::Composition::Carrier;
    namespace Net = boost::asio;
    namespace Restls = Preview::Restls;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    template <typename Awaitable>
    auto RunCoro(Net::io_context &Context, Awaitable Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(
            Context,
            std::move(Operation),
            [&Failure, &Context](std::exception_ptr Exception)
            {
                Failure = std::move(Exception);
                Context.stop();
            });
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

    auto ReadExact(const Preview::SharedTransmission &Transport,
                   std::span<std::byte> Buffer) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            std::error_code ErrorCode;
            const auto Read = co_await Transport->async_read_some(Buffer.subspan(Offset), ErrorCode);
            if (ErrorCode || Read == 0 || Read > Buffer.size() - Offset)
            {
                co_return false;
            }
            Offset += Read;
        }
        co_return true;
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
        Restls::CarrierOptions Options;
        Options.Password = "restls-carrier-password";
        Options.Handover.ServerRandom = ServerRandom;
        Options.Handover.ClientFinished = ClientFinished;
        Options.Handover.FirstEncrypted = FirstEncrypted;
        auto CarrierFacade = Restls::MakeFacadeCarrier(std::move(Options));
        ASSERT_TRUE(CarrierFacade.WireReady());

        std::optional<Carrier::CarrierAcceptResult> Result;
        std::vector<std::uint8_t> ReceivedFirst(FirstEncrypted.size());
        RunCoro(Context,
                [&]() -> Net::awaitable<void>
                {
                    Result = co_await CarrierFacade.Accept(
                        Carrier::CarrierAcceptRequest{ServerTransport, {}, {}});
                    EXPECT_TRUE(Result.has_value());
                    if (!Result.has_value())
                    {
                        co_return;
                    }
                    EXPECT_TRUE(Result->Accepted());
                    if (!Result->Accepted())
                    {
                        co_return;
                    }
                    EXPECT_EQ(Result->Metadata.Kind, Carrier::CarrierKind::Restls);
                    EXPECT_EQ(Result->Metadata.ReplayBytes, 0U);

                    const auto Received = co_await ReadExact(
                        ClientTransport,
                        std::span<std::byte>(reinterpret_cast<std::byte *>(ReceivedFirst.data()),
                                             ReceivedFirst.size()));
                    EXPECT_TRUE(Received);
                });

        ASSERT_TRUE(Result.has_value());
        ASSERT_TRUE(Result->Transport);
        auto Connection = std::dynamic_pointer_cast<Restls::Conn<>>(Result->Transport);
        ASSERT_TRUE(Connection);
        EXPECT_EQ(Connection->NextLayer(), OriginalTransport.get());

        auto ExpectedFirst = FirstEncrypted;
        const auto Secret = Restls::DeriveSecret("restls-carrier-password");
        const auto Mask = Restls::ComputeServerMask(Secret, ServerRandom);
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
        auto Client = std::make_shared<Restls::Conn<>>(ClientTransport, "restls-counter-password");

        RunCoro(Context,
                [&]() -> Net::awaitable<void>
                {
                    EXPECT_EQ(co_await Client->WriteHandshake(ServerRandom, ClientFinished), Error::None);
                    std::error_code ErrorCode;
                    const auto FirstWritten = co_await Client->async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(FirstData.data()),
                                                   FirstData.size()),
                        ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    EXPECT_EQ(FirstWritten, FirstData.size());

                    const auto Secret = Restls::DeriveSecret("restls-counter-password");
                    const auto FirstExpected = Restls::BuildFrame(Restls::FrameOptions{
                        .Secret = Secret,
                        .ServerRandom = ServerRandom,
                        .Direction = Restls::FlowDirection::ToServer,
                        .Counter = 0,
                        .ClientFinished = ClientFinished,
                        .Data = FirstData,
                        .PaddingLength = 0,
                        .Command = Restls::CmdTypeNoop,
                        .CommandArgument = 0});
                    EXPECT_EQ(FirstExpected.first, Error::None);
                    if (FirstExpected.first != Error::None)
                    {
                        co_return;
                    }
                    std::vector<std::byte> FirstWire(FirstExpected.second.size());
                    EXPECT_TRUE(co_await ReadExact(
                        ServerTransport,
                        FirstWire));
                    EXPECT_EQ(std::vector<std::uint8_t>(
                                  reinterpret_cast<const std::uint8_t *>(FirstWire.data()),
                                  reinterpret_cast<const std::uint8_t *>(FirstWire.data()) + FirstWire.size()),
                              FirstExpected.second);

                    const auto SecondWritten = co_await Client->async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(SecondData.data()),
                                                   SecondData.size()),
                        ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    EXPECT_EQ(SecondWritten, SecondData.size());
                    const auto SecondExpected = Restls::BuildFrame(Restls::FrameOptions{
                        .Secret = Secret,
                        .ServerRandom = ServerRandom,
                        .Direction = Restls::FlowDirection::ToServer,
                        .Counter = 1,
                        .ClientFinished = {},
                        .Data = SecondData,
                        .PaddingLength = 0,
                        .Command = Restls::CmdTypeNoop,
                        .CommandArgument = 0});
                    EXPECT_EQ(SecondExpected.first, Error::None);
                    if (SecondExpected.first != Error::None)
                    {
                        co_return;
                    }
                    std::vector<std::byte> SecondWire(SecondExpected.second.size());
                    EXPECT_TRUE(co_await ReadExact(ServerTransport, SecondWire));
                    EXPECT_EQ(std::vector<std::uint8_t>(
                                  reinterpret_cast<const std::uint8_t *>(SecondWire.data()),
                                  reinterpret_cast<const std::uint8_t *>(SecondWire.data()) + SecondWire.size()),
                              SecondExpected.second);
                });
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
        const auto Secret = Restls::DeriveSecret("restls-read-password");
        const auto FirstFrame = Restls::BuildFrame(Restls::FrameOptions{
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
        const auto SecondFrame = Restls::BuildFrame(Restls::FrameOptions{
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
        auto Server = std::make_shared<Restls::Conn<>>(ServerTransport, "restls-read-password");

        RunCoro(Context,
                [&]() -> Net::awaitable<void>
                {
                    EXPECT_EQ(co_await Server->ReadHandshake(ServerRandom, ClientFinished), Error::None);
                    std::error_code ErrorCode;
                    co_await ClientTransport->async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(FirstFrame.second.data()),
                                                   FirstFrame.second.size()),
                        ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    std::array<std::byte, 32> Buffer{};
                    const auto FirstRead = co_await Server->async_read_some(Buffer, ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    EXPECT_EQ(std::vector<std::uint8_t>(
                                  reinterpret_cast<const std::uint8_t *>(Buffer.data()),
                                  reinterpret_cast<const std::uint8_t *>(Buffer.data()) + FirstRead),
                              Data);

                    co_await ClientTransport->async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(SecondFrame.second.data()),
                                                   SecondFrame.second.size()),
                        ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    const auto SecondRead = co_await Server->async_read_some(Buffer, ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    EXPECT_EQ(SecondRead, Data.size());

                    co_await ClientTransport->async_write_some(
                        std::span<const std::byte>(reinterpret_cast<const std::byte *>(FirstFrame.second.data()),
                                                   FirstFrame.second.size()),
                        ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    const auto ReplayRead = co_await Server->async_read_some(Buffer, ErrorCode);
                    EXPECT_EQ(ReplayRead, 0U);
                    EXPECT_EQ(ErrorCode.value(), static_cast<int>(Error::BadAuth));
                });
    }

} // namespace
