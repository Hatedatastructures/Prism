/**
 * @file VlessConnErrorMatrix.cpp
 * @brief VLESS Conn 错误矩阵测试
 * @details 服务端握手错误路径：
 * - UUID 不匹配（bad_auth）
 * - 非法版本（bad_magic）
 * - 非法命令（not_supported）
 * - 非法地址类型（bad_message）
 * - 半包截断（io_error）
 * - 客户端响应校验失败
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <expected>
#include <memory>
#include <string>
#include <vector>

#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <Prism/Protocols/Vless/Codec.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Vless = Prism::Vless;
    using Prism::AsBytes;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;

    auto ExpectFactoryFailure(
        const std::expected<Vless::AcceptedConnection, Prism::Fault::Failure> &Result,
        const Prism::Fault::Code Expected) -> void
    {
        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Code, Expected);
        EXPECT_FALSE(Result.error().Native);
    }

    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    constexpr auto MakeUuid = []() -> std::array<std::uint8_t, 16>
    {
        return {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    };

    auto RunPartialNativeWriteFailure(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<Prism::PrismMockTransport>(IoContext.get_executor());
        const auto Native = std::make_error_code(std::errc::connection_reset);
        Raw->WriteErrorBytes = 1;
        Raw->SetWriteError(Native);
        Vless::ClientConfig Config;
        Config.uuid = MakeUuid();
        const auto Target = Vless::Address{Vless::AddressType::Domain, "example.com", 443};
        auto Result = co_await Vless::Connect(Vless::ConnectParameters{Raw, Config, Target});
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.error().Native, Native);
        EXPECT_EQ(Raw->Written.size(), 1u);
        EXPECT_TRUE(Raw->IsClosed());
        const auto Drain = co_await Raw->Activity()->Drain();
        EXPECT_TRUE(Drain);
    }

    auto RunPartialNativeReadFailure(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<Prism::PrismMockTransport>(IoContext.get_executor());
        const auto Native = std::make_error_code(std::errc::connection_reset);
        Raw->InjectRead({Vless::ProtocolVersion});
        Raw->ReadErrorBytes = 1;
        Raw->SetReadError(Native);
        Vless::ServerConfig Config;
        Config.uuid = MakeUuid();
        auto Result = co_await Vless::Accept(Raw, Config);
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.error().Native, Native);
        EXPECT_EQ(Raw->ReadsDone, 1u);
        (void)Raw->Close();
        EXPECT_TRUE(co_await Raw->Activity()->Drain());
    }

    struct RejectServerRequest final
    {
        std::shared_ptr<MemoryStream> Server;
        Vless::ServerConfig Config;
        Prism::Fault::Code Expected;
    };

    auto AcceptRejectedRequest(RejectServerRequest Request) -> Net::awaitable<void>
    {
        const auto Result = co_await Vless::Accept(Request.Server, Request.Config);
        ExpectFactoryFailure(Result, Request.Expected);
    }

    struct RejectScenario final
    {
        std::vector<std::uint8_t> Wire;
        Prism::Fault::Code Expected;
        bool CloseClientWrite;
        bool AssertWriteSucceeded;
    };

    auto RunServerRejectScenario(
        Net::io_context &IoContext,
        RejectScenario Scenario) -> Net::awaitable<void>
    {
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        Vless::ServerConfig Config;
        Config.uuid = MakeUuid();
        auto Server = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto ServerTask = Net::co_spawn(
            IoContext.get_executor(),
            AcceptRejectedRequest(RejectServerRequest{Server, Config, Scenario.Expected}),
            Net::use_awaitable);
        std::error_code ErrorCode;
        const auto Write = co_await ClientMemory.WriteSome(
            AsBytes(std::span<const std::uint8_t>(Scenario.Wire)));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        if (Scenario.AssertWriteSucceeded)
        {
            EXPECT_FALSE(ErrorCode);
        }
        if (Scenario.CloseClientWrite)
        {
            (void)ClientMemory.Close();
        }
        co_await std::move(ServerTask);
    }

    TEST(VlessCodec, ParseAddressRejectsUnknownAtyp)
    {
        Vless::Address Address;
        std::size_t Offset = 0;
        const std::array<std::uint8_t, 1> Wire{0x09};

        EXPECT_EQ(Vless::ParseAddress(Wire, Address, Offset), Error::BadMessage);
        EXPECT_EQ(Offset, 1u);
    }

    TEST(VlessConnErrorMatrix, PartialHandshakeWritePreservesNativeFailure)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunPartialNativeWriteFailure(IoContext));
    }

    TEST(VlessConnErrorMatrix, PartialHandshakeReadPreservesNativeFailure)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunPartialNativeReadFailure(IoContext));
    }

    TEST(VlessCodec, ParseRequestRejectsUnknownAtyp)
    {
        std::vector<std::uint8_t> Wire{Vless::ProtocolVersion};
        const auto Uuid = MakeUuid();
        Wire.insert(Wire.end(), Uuid.begin(), Uuid.end());
        Wire.insert(Wire.end(), {0x00, static_cast<std::uint8_t>(Vless::Command::Tcp), 0x01, 0xBB,
                                 0x09});
        Vless::RequestHeader Request;
        std::size_t Consumed = 0;

        EXPECT_EQ(Vless::ParseRequest(Wire, Request, Consumed), Error::BadMessage);
    }

    TEST(VlessCodec, ParseAddressKeepsNeedMoreForKnownAtyp)
    {
        Vless::Address Address;
        std::size_t Offset = 0;
        const std::array<std::uint8_t, 3> Wire{static_cast<std::uint8_t>(Vless::AddressType::Ipv4),
                                               127, 0};

        EXPECT_EQ(Vless::ParseAddress(Wire, Address, Offset), Error::NeedMore);
        EXPECT_EQ(Offset, 1u);
    }

    TEST(VlessConnErrorMatrix, BadUuid)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{Vless::ProtocolVersion};
        Wire.insert(Wire.end(), 16, 0xAB); // 错误 UUID
        // addonsLen + cmd + port + atyp + addr(4B)：完整合法请求，仅 UUID 错误
        Wire.insert(Wire.end(), {0x00, 0x01, 0x01, 0xBB, 0x01, 0x01, 0x00, 0x50, 0x01});
        RunCoroutine(IoContext, RunServerRejectScenario(IoContext, RejectScenario{
            std::move(Wire), Prism::Fault::Code::AuthFailed, true, true}));
    }

    TEST(VlessConnErrorMatrix, BadVersion)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{0x99}; // 错误版本
        Wire.insert(Wire.end(), 16, 0x01);
        Wire.insert(Wire.end(), {0x00, 0x01, 0x01, 0xBB, 0x01, 0x01, 0x00, 0x50});
        RunCoroutine(IoContext, RunServerRejectScenario(IoContext, RejectScenario{
            std::move(Wire), Prism::Fault::Code::BadMessage, false, false}));
    }

    TEST(VlessConnErrorMatrix, BadCommand)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{Vless::ProtocolVersion};
        Wire.insert(Wire.end(), 16, 0x01);
        Wire.insert(Wire.end(), {0x00, 0x99, 0x01, 0xBB, 0x01, 0x01, 0x00, 0x50}); // 命令 0x99
        RunCoroutine(IoContext, RunServerRejectScenario(IoContext, RejectScenario{
            std::move(Wire), Prism::Fault::Code::BadMessage, false, false}));
    }

    TEST(VlessConnErrorMatrix, BadAddressType)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{Vless::ProtocolVersion};
        Wire.insert(Wire.end(), 16, 0x01);
        Wire.insert(Wire.end(), {0x00, 0x01, 0x01, 0xBB, 0x09, 0x01, 0x00, 0x50}); // ATYP=9
        RunCoroutine(IoContext, RunServerRejectScenario(IoContext, RejectScenario{
            std::move(Wire), Prism::Fault::Code::BadMessage, false, false}));
    }

    TEST(VlessConnErrorMatrix, TruncatedHeader)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{Vless::ProtocolVersion};
        Wire.insert(Wire.end(), 16, 0x01);
        Wire.insert(Wire.end(), {0x00, 0x01, 0x01, 0xBB}); // 截断
        RunCoroutine(IoContext, RunServerRejectScenario(IoContext, RejectScenario{
            std::move(Wire), Prism::Fault::Code::Eof, true, false}));
    }

} // namespace
