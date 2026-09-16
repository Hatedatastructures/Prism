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
#include <memory>
#include <string>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Vless = Preview::Vless;
    using Preview::AsBytes;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

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

    TEST(VlessCodec, ParseAddressRejectsUnknownAtyp)
    {
        Vless::Address Address;
        std::size_t Offset = 0;
        const std::array<std::uint8_t, 1> Wire{0x09};

        EXPECT_EQ(Vless::ParseAddress(Wire, Address, Offset), Error::BadMessage);
        EXPECT_EQ(Offset, 1u);
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
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            Vless::ServerConfig Config;
            Config.uuid = MakeUuid();

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                EXPECT_EQ(ErrorValue, Error::BadAuth);
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            std::vector<std::uint8_t> Wire{Vless::ProtocolVersion};
            Wire.insert(Wire.end(), 16, 0xAB); // 错误 UUID
            // addonsLen + cmd + port + atyp + addr(4B)：完整合法请求，仅 UUID 错误
            Wire.insert(Wire.end(), {0x00, 0x01, 0x01, 0xBB, 0x01, 0x01, 0x00, 0x50, 0x01});
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            EXPECT_FALSE(ErrorCode);
            ClientMemory.Close();
            co_await std::move(ServerTask);
        });
    }

    TEST(VlessConnErrorMatrix, BadVersion)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            Vless::ServerConfig Config;
            Config.uuid = MakeUuid();

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                EXPECT_EQ(ErrorValue, Error::BadMagic);
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            std::vector<std::uint8_t> Wire{0x99}; // 错误版本
            Wire.insert(Wire.end(), 16, 0x01);
            Wire.insert(Wire.end(), {0x00, 0x01, 0x01, 0xBB, 0x01, 0x01, 0x00, 0x50});
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            co_await std::move(ServerTask);
        });
    }

    TEST(VlessConnErrorMatrix, BadCommand)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            Vless::ServerConfig Config;
            Config.uuid = MakeUuid();

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                EXPECT_EQ(ErrorValue, Error::BadMessage); // 命令 0x99 不在 Tcp/udp/mux 白名单
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            std::vector<std::uint8_t> Wire{Vless::ProtocolVersion};
            Wire.insert(Wire.end(), 16, 0x01);
            Wire.insert(Wire.end(), {0x00, 0x99, 0x01, 0xBB, 0x01, 0x01, 0x00, 0x50}); // 命令 0x99
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            co_await std::move(ServerTask);
        });
    }

    TEST(VlessConnErrorMatrix, BadAddressType)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            Vless::ServerConfig Config;
            Config.uuid = MakeUuid();

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                EXPECT_EQ(ErrorValue, Error::BadMessage); // ATYP=9 非法
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            std::vector<std::uint8_t> Wire{Vless::ProtocolVersion};
            Wire.insert(Wire.end(), 16, 0x01);
            Wire.insert(Wire.end(), {0x00, 0x01, 0x01, 0xBB, 0x09, 0x01, 0x00, 0x50}); // ATYP=9
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            co_await std::move(ServerTask);
        });
    }

    TEST(VlessConnErrorMatrix, TruncatedHeader)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            Vless::ServerConfig Config;
            Config.uuid = MakeUuid();

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Conn] = co_await Vless::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                EXPECT_EQ(ErrorValue, Error::IoError); // 半包后 EOF
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            std::vector<std::uint8_t> Wire{Vless::ProtocolVersion};
            Wire.insert(Wire.end(), 16, 0x01);
            Wire.insert(Wire.end(), {0x00, 0x01, 0x01, 0xBB}); // 截断
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            ClientMemory.Close();
            co_await std::move(ServerTask);
        });
    }

} // namespace
