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

#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Net/Dns/Resolver.hpp>
#include <preview/Net/Target.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using namespace Preview;

    using Preview::Testing::RunCoro; // 公共样板（见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）

    // DNS 感知拨号：域名先经 Resolver 解析为 IP 再 Dialer.Connect
    auto dial_with_dns(net::any_io_executor ex, const Network::Target &tgt)
        -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
    {
        std::error_code ec;
        // 尝试直接解析为 IP
        boost::system::error_code bec;
        auto addr = net::ip::make_address(std::string(tgt.Host), bec);
        if (!bec)
        {
            Network::Dialer::Dialer d(ex);
            std::string port_str(tgt.Port);
            unsigned short port = static_cast<unsigned short>(std::stoi(port_str));
            auto tr = co_await d.Connect(tgt.Host, port, ec);
            if (ec || !tr) co_return std::pair{Fault::Code::Unreachable, SharedTransmission{}};
            co_return std::pair{Fault::Code::Success, std::move(tr)};
        }
        // 域名：经 Resolver 解析
        Network::Dns::Resolver Resolver(ex);
        std::error_code rec;
        auto addrs = co_await Resolver.AsyncResolve(std::string(tgt.Host), rec);
        if (rec || addrs.empty())
        {
            co_return std::pair{Fault::Code::Unreachable, SharedTransmission{}};
        }
        for (const auto &a : addrs)
        {
            Network::Dialer::Dialer d(ex);
            std::string port_str(tgt.Port);
            unsigned short port = static_cast<unsigned short>(std::stoi(port_str));
            auto tr = co_await d.Connect(a.to_string(), port, ec);
            if (!ec && tr) co_return std::pair{Fault::Code::Success, std::move(tr)};
        }
        co_return std::pair{Fault::Code::Unreachable, SharedTransmission{}};
    }

    TEST(DnsResolver, ResolveLocalhost)
    {
        net::io_context ioc;
        bool Ok = false;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            Network::Dns::Resolver Resolver(ioc.get_executor());
            std::error_code ec;
            auto addrs = co_await Resolver.AsyncResolve("localhost", ec);
            EXPECT_FALSE(ec);
            EXPECT_FALSE(addrs.empty());
            // 缓存命中
            auto addrs2 = co_await Resolver.AsyncResolve("localhost", ec);
            EXPECT_FALSE(ec);
            EXPECT_GT(Resolver.HitCount(), 0u);
            Ok = !addrs.empty();
        }, [&](std::exception_ptr ep){ if(ep) std::rethrow_exception(ep); ioc.stop(); });
        ioc.run();
        EXPECT_TRUE(Ok);
    }

    TEST(DnsResolver, NegativeCache)
    {
        net::io_context ioc;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            Network::Dns::Resolver Resolver(ioc.get_executor());
            std::error_code ec;
            auto addrs = co_await Resolver.AsyncResolve("nonexistent12345.test.invalid", ec);
            // 第二次应命中缓存（无论正/负）
            std::error_code ec2;
            auto addrs2 = co_await Resolver.AsyncResolve("nonexistent12345.test.invalid", ec2);
            EXPECT_GT(Resolver.HitCount(), 0u);
            EXPECT_EQ(addrs.size(), addrs2.size());
            EXPECT_EQ(!!ec, !!ec2);
        }, [&](std::exception_ptr ep){ if(ep) std::rethrow_exception(ep); ioc.stop(); });
        ioc.run();
    }

    TEST(DnsDial, SessionDialViaDns)
    {
        net::io_context ioc;
        // echo Server
        Tcp::acceptor echo_ac(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_ac.local_endpoint().port();
        net::co_spawn(ioc.get_executor(), [&]() -> net::awaitable<void>
        {
            while (true)
            {
                boost::system::error_code ec;
                auto sock = co_await echo_ac.async_accept(net::redirect_error(net::use_awaitable, ec));
                if (ec) co_return;
                std::array<std::byte, 4096> buf{};
                auto n = co_await sock.async_read_some(net::buffer(buf), net::redirect_error(net::use_awaitable, ec));
                if (ec || n==0) continue;
                co_await sock.async_write_some(net::buffer(buf,n), net::redirect_error(net::use_awaitable, ec));
            }
        }, net::detached);

        bool Ok = false;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            Network::Target tgt;
            tgt.Host = "127.0.0.1";
            tgt.Port = std::to_string(echo_port);
            auto [Code, tr] = co_await dial_with_dns(ioc.get_executor(), tgt);
            EXPECT_EQ(Code, Fault::Code::Success);
            if (!tr) { ADD_FAILURE() << "tr null"; co_return; }
            // 透传验证
            const std::string payload = "dns Dial";
            std::error_code ec;
            co_await tr->AsyncWrite(std::span<const std::byte>(reinterpret_cast<const std::byte*>(payload.data()), payload.size()), ec);
            EXPECT_FALSE(ec);
            std::array<std::byte, 64> buf{};
            auto n = co_await tr->async_read_some(buf, ec);
            EXPECT_FALSE(ec);
            std::string echo(reinterpret_cast<char*>(buf.data()), n);
            Ok = (echo == payload);
            tr->Close();
            boost::system::error_code ce;
            echo_ac.close(ce);
        }, [&](std::exception_ptr ep){ if(ep) std::rethrow_exception(ep); ioc.stop(); });
        ioc.run();
        EXPECT_TRUE(Ok);
    }

} // namespace
