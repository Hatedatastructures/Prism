/**
 * @file ShadowtlsCarrierTest.cpp
 * @brief ShadowTLS server-side Composition carrier 的真实 wire/transport 测试。
 */

#include <Preview/Composition/Carrier/FacadeCarrier.hpp>
#include <Preview/Composition/Recognition/ShadowtlsCarrier.hpp>
#include <Preview/Protocols/Shadowtls/Codec.hpp>
#include <Preview/Protocols/Shadowtls/Shadowtls.hpp>
#include <Preview/Transport/MemoryStream.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <exception>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{

    namespace Carrier = Preview::Composition::Carrier;
    namespace Net = boost::asio;
    namespace Shadowtls = Preview::Shadowtls;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;

    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &Context, Awaitable Task) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(
            Context,
            std::move(Task),
            [&](std::exception_ptr ErrorValue)
            {
                Failure = std::move(ErrorValue);
                Context.stop();
            });
        Context.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    [[nodiscard]] auto MakeClientHelloTemplate() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(75, 0);
        Hello[0] = 0x03;
        Hello[1] = 0x03;
        for (std::size_t Index = 0; Index < Shadowtls::TlsRndSize; ++Index)
        {
            Hello[2 + Index] = static_cast<std::uint8_t>(0x20 + Index);
        }
        Hello[34] = Shadowtls::TlsSessionIdSz;
        Hello[67] = 0;
        Hello[68] = 2;
        Hello[69] = 0x13;
        Hello[70] = 0x01;
        Hello[71] = 1;
        Hello[72] = 0;
        Hello[73] = 0;
        Hello[74] = 0;

        std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + 4 + Hello.size(), 0);
        Record[0] = 0x16;
        Record[1] = 0x03;
        Record[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(4 + Hello.size());
        Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Record[4] = static_cast<std::uint8_t>(BodyLength);
        Record[5] = Shadowtls::HsTypeClienthello;
        Record[7] = 0;
        Record[8] = static_cast<std::uint8_t>(Hello.size());
        std::copy(Hello.begin(), Hello.end(), Record.begin() + 9);
        return Record;
    }

    [[nodiscard]] auto MakeServerHello() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(78, 0);
        Hello[0] = 0x03;
        Hello[1] = 0x03;
        for (std::size_t Index = 0; Index < Shadowtls::TlsRndSize; ++Index)
        {
            Hello[2 + Index] = static_cast<std::uint8_t>(0x80 + Index);
        }
        Hello[34] = Shadowtls::TlsSessionIdSz;
        Hello[67] = 0x13;
        Hello[68] = 0x01;
        Hello[69] = 0;
        Hello[70] = 0;
        Hello[71] = 6;
        Hello[72] = 0;
        Hello[73] = 43;
        Hello[74] = 0;
        Hello[75] = 2;
        Hello[76] = 3;
        Hello[77] = 4;

        std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + 4 + Hello.size(), 0);
        Record[0] = 0x16;
        Record[1] = 0x03;
        Record[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(4 + Hello.size());
        Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Record[4] = static_cast<std::uint8_t>(BodyLength);
        Record[5] = 2;
        Record[7] = static_cast<std::uint8_t>(Hello.size() >> 8);
        Record[8] = static_cast<std::uint8_t>(Hello.size());
        std::copy(Hello.begin(), Hello.end(), Record.begin() + 9);
        return Record;
    }

    [[nodiscard]] auto ReadExactBytes(const SharedTransmission &Transport,
                                       std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
    {
        std::fprintf(stderr, "read exact start size=%zu transport=%p\n", Buffer.size(), Transport.get());
        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            std::error_code ErrorCode;
            auto Window = std::span<std::byte>(
                reinterpret_cast<std::byte *>(Buffer.data() + Done), Buffer.size() - Done);
            const auto Count = co_await Transport->async_read_some(Window, ErrorCode);
            std::fprintf(stderr, "read exact result size=%zu count=%zu ec=%d\n", Buffer.size(), Count,
                         ErrorCode.value());
            if (ErrorCode || Count == 0 || Count > Buffer.size() - Done)
            {
                co_return false;
            }
            Done += Count;
        }
        co_return true;
    }

    [[nodiscard]] auto WriteAllBytes(const SharedTransmission &Transport,
                                     std::span<const std::uint8_t> Buffer) -> Net::awaitable<bool>
    {
        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            std::error_code ErrorCode;
            const auto Window = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Buffer.data() + Done), Buffer.size() - Done);
            const auto Count = co_await Transport->async_write_some(Window, ErrorCode);
            if (ErrorCode || Count == 0 || Count > Buffer.size() - Done)
            {
                co_return false;
            }
            Done += Count;
        }
        co_return true;
    }

    [[nodiscard]] auto ReadRecord(const SharedTransmission &Transport,
                                  std::vector<std::uint8_t> &Record) -> Net::awaitable<bool>
    {
        std::array<std::uint8_t, Shadowtls::TlsHdrsize> Header{};
        if (!co_await ReadExactBytes(Transport, Header))
        {
            co_return false;
        }
        const auto Length = (static_cast<std::size_t>(Header[3]) << 8) | Header[4];
        Record.resize(Shadowtls::TlsHdrsize + Length);
        std::copy(Header.begin(), Header.end(), Record.begin());
        co_return co_await ReadExactBytes(
            Transport, std::span<std::uint8_t>(Record).subspan(Shadowtls::TlsHdrsize));
    }

    TEST(ShadowtlsCarrier, RequiresTargetDialBeforeReportingWireReady)
    {
        const auto CarrierValue = Preview::Composition::Recognition::MakeShadowtlsCarrier(
            Shadowtls::ServerOptions{}, Shadowtls::ServerConfig{"carrier-password"});
        EXPECT_FALSE(CarrierValue.WireReady());
        EXPECT_EQ(CarrierValue.Kind(), Carrier::CarrierKind::Shadowtls);
        EXPECT_FALSE(CarrierValue.Blocker().empty());
    }

    TEST(ShadowtlsCarrier, AcceptsAuthenticatedWireAndReturnsProtectedTransport)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());
        auto [TargetEndpoint, TargetClientEndpoint] = MakeMemoryPair(Context.get_executor());
        const auto Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
        const auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
        const auto Target = std::make_shared<MemoryStream>(std::move(TargetEndpoint));
        const auto TargetClient = std::make_shared<MemoryStream>(std::move(TargetClientEndpoint));
        const auto ServerHello = MakeServerHello();
        const auto Password = std::string{"carrier-password"};
        const auto ClientPayload = std::vector<std::uint8_t>{0x31, 0x32, 0x33, 0x34};
        const auto ServerPayload = std::vector<std::uint8_t>{0xa1, 0xa2, 0xa3};
        const auto TargetDone = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            Context.get_executor(), 1);
        const auto TargetObserved = std::make_shared<std::vector<std::uint8_t>>();

        Shadowtls::ServerOptions Options;
        Options.DialTarget = [Target, TargetClient, ServerHello, TargetDone, TargetObserved](
                                 std::span<const std::uint8_t>)
            -> Net::awaitable<SharedTransmission>
        {
            Net::co_spawn(
                TargetClient->Executor(),
                [TargetClient, ServerHello, TargetDone, TargetObserved]() -> Net::awaitable<void>
                {
                    std::fprintf(stderr, "target: start\n");
                    std::vector<std::uint8_t> Forwarded;
                    if (!co_await ReadRecord(TargetClient, Forwarded))
                    {
                        std::fprintf(stderr, "target: read client hello failed\n");
                        TargetDone->try_send(boost::system::error_code{});
                        co_return;
                    }
                    std::fprintf(stderr, "target: read client hello\n");
                    *TargetObserved = Forwarded;
                    if (!co_await WriteAllBytes(TargetClient, ServerHello))
                    {
                        std::fprintf(stderr, "target: write server hello failed\n");
                        TargetDone->try_send(boost::system::error_code{});
                        co_return;
                    }
                    std::fprintf(stderr, "target: wrote server hello\n");
                    std::array<std::byte, 1> Buffer{};
                    std::error_code ErrorCode;
                    (void)co_await TargetClient->async_read_some(Buffer, ErrorCode);
                    std::fprintf(stderr, "target: target closed\n");
                    TargetDone->try_send(boost::system::error_code{});
                },
                Net::detached);
            co_return Target;
        };

        const auto CarrierValue = Preview::Composition::Recognition::MakeShadowtlsCarrier(
            std::move(Options), Shadowtls::ServerConfig{Password});
        ASSERT_TRUE(CarrierValue.WireReady());

        RunCoroutine(
            Context,
            [&]() -> Net::awaitable<void>
            {
                std::fprintf(stderr, "client: start\n");
                const auto ClientConfig = Shadowtls::ClientConfig{Password};
                auto AcceptTask = Net::co_spawn(
                    Context,
                    CarrierValue.Accept(Carrier::CarrierAcceptRequest{Server, {}, {}}),
                    Net::use_awaitable);
                auto [ClientError, ClientConnection] = co_await Shadowtls::ConnectStandard(
                    Shadowtls::StandardConnectParameters{Client, ClientConfig, MakeClientHelloTemplate()});
                EXPECT_EQ(ClientError, Error::None);
                std::fprintf(stderr, "client: standard hello sent\n");
                EXPECT_TRUE(ClientConnection);
                if (!ClientConnection)
                {
                    co_return;
                }

                auto ClientTransport = std::static_pointer_cast<Preview::Transmission>(ClientConnection);
                Client->SetTimeout(std::chrono::milliseconds(1000));
                std::vector<std::uint8_t> ReceivedServerHello;
                const auto ReceivedServerHelloOk = co_await ReadRecord(ClientTransport, ReceivedServerHello);
                if (!ReceivedServerHelloOk)
                {
                    const auto FailureResult = co_await std::move(AcceptTask);
                    std::fprintf(stderr, "carrier: accepted=%d failure=%d protocol=%d detail=%s\n",
                                 FailureResult.Accepted(),
                                 static_cast<int>(FailureResult.Failure.Code),
                                 static_cast<int>(FailureResult.Failure.ProtocolCode),
                                 FailureResult.Failure.Detail.c_str());
                    EXPECT_TRUE(false) << "server hello was not relayed";
                    co_return;
                }
                EXPECT_TRUE(ReceivedServerHelloOk);
                std::fprintf(stderr, "client: server hello read\n");
                EXPECT_EQ(ReceivedServerHello, ServerHello);

                std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom{};
                std::copy(ServerHello.begin() + 11, ServerHello.begin() + 11 + ServerRandom.size(),
                          ServerRandom.begin());
                EXPECT_EQ(ClientConnection->EnableRecordProtection(ServerRandom), Error::None);
                std::error_code ErrorCode;
                const auto Written = co_await ClientConnection->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(ClientPayload.data()),
                                               ClientPayload.size()),
                    ErrorCode);
                EXPECT_FALSE(ErrorCode);
                EXPECT_EQ(Written, ClientPayload.size());
                std::fprintf(stderr, "client: application record sent\n");

                const auto Result = co_await std::move(AcceptTask);
                std::fprintf(stderr, "client: carrier result received\n");
                EXPECT_TRUE(Result.Accepted());
                EXPECT_EQ(Result.Metadata.Kind, Carrier::CarrierKind::Shadowtls);
                EXPECT_TRUE(Result.Metadata.WireComplete);
                EXPECT_EQ(Result.Metadata.ReplayBytes, 0U);
                EXPECT_TRUE(Result.State);
                if (!Result.State)
                {
                    co_return;
                }
                EXPECT_EQ(Result.State->Current(), Carrier::HandshakeStage::Accepted);
                EXPECT_TRUE(Result.Transport);
                if (!Result.Transport)
                {
                    co_return;
                }
                EXPECT_EQ(*TargetObserved, ClientConnection->TakeClientHelloWire());
                std::fprintf(stderr, "client: result transport verified\n");

                std::array<std::byte, 32> ServerReadBuffer{};
                const auto ReadCount = co_await Result.Transport->async_read_some(ServerReadBuffer, ErrorCode);
                EXPECT_FALSE(ErrorCode);
                EXPECT_EQ(std::vector<std::uint8_t>(
                              reinterpret_cast<const std::uint8_t *>(ServerReadBuffer.data()),
                              reinterpret_cast<const std::uint8_t *>(ServerReadBuffer.data()) + ReadCount),
                          ClientPayload);
                std::fprintf(stderr, "client: pending payload read\n");

                const auto ServerWritten = co_await Result.Transport->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(ServerPayload.data()),
                                               ServerPayload.size()),
                    ErrorCode);
                EXPECT_FALSE(ErrorCode);
                EXPECT_EQ(ServerWritten, ServerPayload.size());
                std::fprintf(stderr, "client: server response written\n");

                std::array<std::byte, 32> ClientReadBuffer{};
                const auto ClientReadCount = co_await ClientConnection->async_read_some(ClientReadBuffer, ErrorCode);
                EXPECT_FALSE(ErrorCode);
                EXPECT_EQ(std::vector<std::uint8_t>(
                              reinterpret_cast<const std::uint8_t *>(ClientReadBuffer.data()),
                              reinterpret_cast<const std::uint8_t *>(ClientReadBuffer.data()) + ClientReadCount),
                          ServerPayload);
                std::fprintf(stderr, "client: server response read\n");

                Result.Transport->Close();
                ClientConnection->Close();
                co_await TargetDone->async_receive(Net::use_awaitable);
                std::fprintf(stderr, "client: target done\n");
            });
    }

} // namespace
