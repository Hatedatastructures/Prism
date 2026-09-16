/**
 * @file DnsDialE2ETest.cpp
 * @brief DNS 解析接入拨号验证
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <memory>
#include <string>

#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Net/Target.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Preview::Fault;
    namespace Network = Preview::Network;
    using Tcp = Net::ip::tcp;
    using Preview::SharedTransmission;
    using Preview::Testing::RunCoro; // 公共样板（见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）

    // DNS 感知拨号：域名先经 Resolver 解析为 IP 再 Dialer.Connect
    auto DialWithDns(Net::any_io_executor Executor, const Network::Target &Target)
        -> Net::awaitable<std::pair<Fault::Code, SharedTransmission>>
    {
        std::error_code ErrorCode;
        // 尝试直接解析为 IP
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(std::string(Target.Host), AddressError);
        if (!AddressError)
        {
            Network::Dialer::Dialer Dialer(Executor);
            const auto Port = static_cast<unsigned short>(std::stoi(std::string(Target.Port)));
            auto Transmission = co_await Dialer.Connect(Target.Host, Port, ErrorCode);
            if (ErrorCode || !Transmission)
            {
                co_return std::pair{Fault::Code::Unreachable, SharedTransmission{}};
            }
            co_return std::pair{Fault::Code::Success, std::move(Transmission)};
        }
        // 域名：经 Resolver 解析
        Network::Dns::Resolver Resolver(Executor);
        std::error_code ResolveError;
        auto Addresses = co_await Resolver.AsyncResolve(std::string(Target.Host), ResolveError);
        if (ResolveError || Addresses.empty())
        {
            co_return std::pair{Fault::Code::Unreachable, SharedTransmission{}};
        }
        for (const auto &AddressValue : Addresses)
        {
            Network::Dialer::Dialer Dialer(Executor);
            const auto Port = static_cast<unsigned short>(std::stoi(std::string(Target.Port)));
            auto Transmission = co_await Dialer.Connect(AddressValue.to_string(), Port, ErrorCode);
            if (!ErrorCode && Transmission)
            {
                co_return std::pair{Fault::Code::Success, std::move(Transmission)};
            }
        }
        co_return std::pair{Fault::Code::Unreachable, SharedTransmission{}};
    }

    TEST(DnsResolver, ResolveLocalhost)
    {
        Net::io_context IoContext;
        bool Ok = false;
        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            Network::Dns::Resolver Resolver(IoContext.get_executor());
            std::error_code ErrorCode;
            auto Addresses = co_await Resolver.AsyncResolve("localhost", ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_FALSE(Addresses.empty());
            // 缓存命中
            auto CachedAddresses = co_await Resolver.AsyncResolve("localhost", ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_GT(Resolver.HitCount(), 0u);
            Ok = !Addresses.empty() && !CachedAddresses.empty();
        }, [&](std::exception_ptr Exception)
        {
            if (Exception)
            {
                std::rethrow_exception(Exception);
            }
            IoContext.stop();
        });
        IoContext.run();
        EXPECT_TRUE(Ok);
    }

    TEST(DnsResolver, NegativeCache)
    {
        Net::io_context IoContext;
        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            Network::Dns::Resolver Resolver(IoContext.get_executor());
            std::error_code ErrorCode;
            auto Addresses = co_await Resolver.AsyncResolve("nonexistent12345.test.invalid", ErrorCode);
            // 第二次应命中缓存（无论正/负）
            std::error_code CachedError;
            auto CachedAddresses = co_await Resolver.AsyncResolve("nonexistent12345.test.invalid", CachedError);
            EXPECT_GT(Resolver.HitCount(), 0u);
            EXPECT_EQ(Addresses.size(), CachedAddresses.size());
            EXPECT_EQ(!!ErrorCode, !!CachedError);
        }, [&](std::exception_ptr Exception)
        {
            if (Exception)
            {
                std::rethrow_exception(Exception);
            }
            IoContext.stop();
        });
        IoContext.run();
    }

    TEST(DnsDial, SessionDialViaDns)
    {
        Net::io_context IoContext;
        // echo Server
        Tcp::acceptor EchoAcceptor(IoContext, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto EchoPort = EchoAcceptor.local_endpoint().port();
        Net::co_spawn(IoContext.get_executor(), [&]() -> Net::awaitable<void>
        {
            while (true)
            {
                boost::system::error_code ErrorCode;
                auto Socket = co_await EchoAcceptor.async_accept(Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode)
                {
                    co_return;
                }
                std::array<std::byte, 4096> Buffer{};
                const auto BytesRead = co_await Socket.async_read_some(
                    Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode || BytesRead == 0)
                {
                    continue;
                }
                co_await Socket.async_write_some(
                    Net::buffer(Buffer, BytesRead), Net::redirect_error(Net::use_awaitable, ErrorCode));
            }
        }, Net::detached);

        bool Ok = false;
        Net::co_spawn(IoContext, [&]() -> Net::awaitable<void>
        {
            Network::Target Target;
            Target.Host = "127.0.0.1";
            Target.Port = std::to_string(EchoPort);
            auto [Code, Transmission] = co_await DialWithDns(IoContext.get_executor(), Target);
            EXPECT_EQ(Code, Fault::Code::Success);
            if (!Transmission)
            {
                ADD_FAILURE() << "transmission null";
                co_return;
            }
            // 透传验证
            const std::string Payload = "dns Dial";
            std::error_code ErrorCode;
            co_await Transmission->AsyncWrite(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()),
                ErrorCode);
            EXPECT_FALSE(ErrorCode);
            std::array<std::byte, 64> Buffer{};
            const auto BytesRead = co_await Transmission->async_read_some(Buffer, ErrorCode);
            EXPECT_FALSE(ErrorCode);
            const std::string Echo(reinterpret_cast<const char *>(Buffer.data()), BytesRead);
            Ok = Echo == Payload;
            Transmission->Close();
            boost::system::error_code CloseError;
            EchoAcceptor.close(CloseError);
        }, [&](std::exception_ptr Exception)
        {
            if (Exception)
            {
                std::rethrow_exception(Exception);
            }
            IoContext.stop();
        });
        IoContext.run();
        EXPECT_TRUE(Ok);
    }

} // namespace
