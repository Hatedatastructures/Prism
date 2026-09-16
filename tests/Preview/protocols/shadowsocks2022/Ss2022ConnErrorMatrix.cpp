/**
 * @file Ss2022ConnErrorMatrix.cpp
 * @brief Shadowsocks 2022 Conn 错误矩阵测试
 * @details 服务端握手错误路径：
 * - 密码不匹配（PSK 派生差异 → AEAD 解密失败 → bad_auth）
 * - 半包截断（salt 未收满 → io_error）
 * @note 客户端连接失败后由服务端关闭底层流解除读阻塞。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Account/Directory.hpp>
#include <Preview/Foundation/Authenticator.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>

namespace
{
    namespace Preview = ::Preview;
    namespace Net = boost::asio;
    namespace SS2022 = Preview::Shadowsocks2022;
    using Preview::AsBytes;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    /**
     * @brief 驱动协程运行
     */
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

    TEST(Ss2022ConnErrorMatrix, BadPassword)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            // 服务端正确密码，客户端错误密码
            SS2022::ServerConfig ServerConfig;
            ServerConfig.password = "Server-correct";
            auto ServerStream = std::make_shared<MemoryStream>(std::move(ServerMemory));

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Connection] = co_await SS2022::Accept(
                    ServerStream, ServerConfig);
                EXPECT_EQ(ErrorValue, Error::BadAuth); // 错误密码 → 固定头解密失败
                ServerStream->Close();                 // 解除客户端响应读取阻塞（EOF）
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            // 客户端用错误密码握手：首包正常发送，但响应校验失败
            SS2022::ClientConfig ClientConfig;
            ClientConfig.password = "Client-wrong";
            auto [ErrorValue, Connection] = co_await SS2022::Connect(
                std::make_shared<MemoryStream>(std::move(ClientMemory)), ClientConfig,
                SS2022::Address{SS2022::AddressType::Domain, "t.internal", 443});
            // 客户端侧：错误密码 → 服务端静默断开（bad_auth 后不写响应）→ 读响应 EOF
            EXPECT_EQ(ErrorValue, Error::IoError);
        });
    }

    TEST(Ss2022ConnErrorMatrix, DirectoryPskAuthTransfersAccountLease)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const std::array<std::uint8_t, 16> Psk{
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30};
        const std::string PskBytes(reinterpret_cast<const char *>(Psk.data()), Psk.size());
        const auto Record = std::make_shared<const Preview::Account::AccountRecord>(
            Preview::Account::AccountRecord::CreateRequest{
                .AccountId = Preview::AccountId{7401},
                .CredentialValue = Preview::Account::Credential::Psk(PskBytes),
                .Quota = {.MaxConnections = 1}});
        Preview::Account::AccountDirectory Directory;
        ASSERT_TRUE(Directory.Upsert(Record));
        auto Authenticator = std::make_shared<Preview::DirectoryAuthenticator>(&Directory);

        RunCoroutine(IoContext,
                     [&]() -> Net::awaitable<void>
                     {
                         Net::experimental::channel<void(boost::system::error_code)> Done(
                             IoContext.get_executor(), 1);
                         SS2022::ServerConfig ServerConfig;
                         ServerConfig.UsePsk = true;
                         ServerConfig.Psk = Psk;
                         ServerConfig.AuthenticatorOwner = Authenticator;
                         auto ServerCoroutine = [&]() -> Net::awaitable<void>
                         {
                             auto [ErrorValue, Request, Connection] = co_await SS2022::Accept(
                                 std::make_shared<MemoryStream>(std::move(ServerMemory)), ServerConfig);
                             EXPECT_EQ(ErrorValue, Error::None);
                             if (ErrorValue == Error::None && Connection)
                             {
                                 auto Lease = Connection->TakeAuthLease();
                                 EXPECT_EQ(Connection->AccountId(), Preview::AccountId{7401});
                                 EXPECT_TRUE(Lease);
                                 EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
                                 Lease.Release();
                                 Lease.Release();
                                 EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
                                 Connection->Close();
                             }
                             (void)Request;
                             (void)Done.try_send(boost::system::error_code{});
                         };
                         Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

                         SS2022::ClientConfig ClientConfig;
                         ClientConfig.UsePsk = true;
                         ClientConfig.Psk = Psk;
                         auto [ErrorValue, Client] = co_await SS2022::Connect(
                             std::make_shared<MemoryStream>(std::move(ClientMemory)),
                             ClientConfig,
                             SS2022::Address{SS2022::AddressType::Domain, "account.test", 443});
                         EXPECT_EQ(ErrorValue, Error::None);
                         if (Client)
                         {
                             Client->Close();
                         }
                         co_await Done.async_receive(Net::use_awaitable);
                     });
    }

    TEST(Ss2022ConnErrorMatrix, TruncatedHeader)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
        {
            SS2022::ServerConfig Config;
            Config.password = "Server-Secret";

            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ErrorValue, Request, Connection] = co_await SS2022::Accept(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)), Config);
                EXPECT_EQ(ErrorValue, Error::IoError); // 半包后 EOF
            };
            Net::co_spawn(IoContext.get_executor(), ServerCoroutine(), Net::detached);

            // 只发 4 字节（salt 未收满）后关闭
            const std::vector<std::uint8_t> Wire{0x01, 0x02, 0x03, 0x04};
            std::error_code ErrorCode;
            co_await ClientMemory.async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
            ClientMemory.Close();
        });
    }

    TEST(Ss2022ConnErrorMatrix, RejectsOverreportedRead)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportRead = true;

        RunCoroutine(IoContext,
                     [&]() -> Net::awaitable<void>
                     {
                         auto Server = std::make_shared<SS2022::Conn<>>(std::string("Server-Secret"));
                         auto [ErrorValue, Request] = co_await Server->ReadHandshake(Raw);
                         EXPECT_EQ(ErrorValue, Error::IoError);
                         EXPECT_EQ(Raw->ReadsDone, 1u);
                         (void)Request;
                     });
    }

    TEST(Ss2022ConnErrorMatrix, RejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportWrite = true;
        Raw->EofOnDrain = true;

        RunCoroutine(IoContext,
                     [&]() -> Net::awaitable<void>
                     {
                         auto Client = std::make_shared<SS2022::Conn<>>(std::string("Server-Secret"));
                         const auto ErrorValue = co_await Client->WriteHandshake(
                             Raw, SS2022::Address{SS2022::AddressType::Domain, "example.com", 443});
                         EXPECT_EQ(ErrorValue, Error::IoError);
                         EXPECT_EQ(Raw->ReadsDone, 0u);
                     });
    }

} // namespace
