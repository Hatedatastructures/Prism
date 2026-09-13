/**
 * @file VmessConnErrorMatrix.cpp
 * @brief VMess Conn 错误矩阵测试
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

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Vmess/Vmess.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Vmess = Preview::Vmess;
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



    TEST(VmessConnErrorMatrix, TruncatedHeader)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            Vmess::ServerConfig Config;
            Config.uuid = MakeUuid();

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Conn] = co_await Vmess::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                EXPECT_EQ(ErrorValue, Preview::Error::IoError); // 只发 4 字节后 EOF（len_enc 读不满）
            };
            auto ServerTask = Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::use_awaitable);

            // 只发 4 字节（半包）
            const std::vector<std::uint8_t> Wire{0x01, 0x02, 0x03, 0x04};
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            ClientMemory.Close();
            co_await std::move(ServerTask);
        });
    }

    TEST(VmessConnErrorMatrix, ClientHandshakeRejectsAuthNonceRandomFailure)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        (void)ServerMemory;
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            const auto Uuid = MakeUuid();
            int Calls = 0;
            const Vmess::RandomSource Source = [&Calls](std::uint8_t *Bytes, int Size)
            {
                ++Calls;
                if (Calls == 5)
                {
                    return 0;
                }
                for (int I = 0; I < Size; ++I)
                {
                    Bytes[I] = 0x42;
                }
                return 1;
            };
            auto Client = std::make_shared<Vmess::Conn<>>(Uuid, Source);
            Vmess::Address Target;
            Target.Type = Vmess::AddressType::Domain;
            Target.Host = "example.com";
            Target.Port = 443;
            const auto Err = co_await Client->WriteHandshake(
                std::make_shared<MemoryStream>(std::move(ClientMemory)), Target);
            EXPECT_EQ(Err, Error::CryptoError);
            EXPECT_EQ(Calls, 5);
        });
    }

} // namespace
