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

#include <common/core/net/dialer/dialer.hpp>
#include <common/core/net/dns/resolver.hpp>
#include <common/core/net/target.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace preview;

    using psm::testing::run_coro; // 公共样板（见 <common/RuntimeTestHelpers.hpp>）

    // DNS 感知拨号：域名先经 resolver 解析为 IP 再 dialer.connect
    auto dial_with_dns(net::any_io_executor ex, const network::target &tgt)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        std::error_code ec;
        // 尝试直接解析为 IP
        boost::system::error_code bec;
        auto addr = net::ip::make_address(std::string(tgt.host), bec);
        if (!bec)
        {
            network::dialer::dialer d(ex);
            std::string port_str(tgt.port);
            unsigned short port = static_cast<unsigned short>(std::stoi(port_str));
            auto tr = co_await d.connect(tgt.host, port, ec);
            if (ec || !tr) co_return std::pair{fault::code::unreachable, shared_transmission{}};
            co_return std::pair{fault::code::success, std::move(tr)};
        }
        // 域名：经 resolver 解析
        network::dns::resolver resolver(ex);
        std::error_code rec;
        auto addrs = co_await resolver.async_resolve(std::string(tgt.host), rec);
        if (rec || addrs.empty())
        {
            co_return std::pair{fault::code::unreachable, shared_transmission{}};
        }
        for (const auto &a : addrs)
        {
            network::dialer::dialer d(ex);
            std::string port_str(tgt.port);
            unsigned short port = static_cast<unsigned short>(std::stoi(port_str));
            auto tr = co_await d.connect(a.to_string(), port, ec);
            if (!ec && tr) co_return std::pair{fault::code::success, std::move(tr)};
        }
        co_return std::pair{fault::code::unreachable, shared_transmission{}};
    }

    TEST(DnsResolver, ResolveLocalhost)
    {
        net::io_context ioc;
        bool ok = false;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            network::dns::resolver resolver(ioc.get_executor());
            std::error_code ec;
            auto addrs = co_await resolver.async_resolve("localhost", ec);
            EXPECT_FALSE(ec);
            EXPECT_FALSE(addrs.empty());
            // 缓存命中
            auto addrs2 = co_await resolver.async_resolve("localhost", ec);
            EXPECT_FALSE(ec);
            EXPECT_GT(resolver.hit_count(), 0u);
            ok = !addrs.empty();
        }, [&](std::exception_ptr ep){ if(ep) std::rethrow_exception(ep); ioc.stop(); });
        ioc.run();
        EXPECT_TRUE(ok);
    }

    TEST(DnsResolver, NegativeCache)
    {
        net::io_context ioc;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            network::dns::resolver resolver(ioc.get_executor());
            std::error_code ec;
            auto addrs = co_await resolver.async_resolve("nonexistent12345.test.invalid", ec);
            // 第二次应命中缓存（无论正/负）
            std::error_code ec2;
            auto addrs2 = co_await resolver.async_resolve("nonexistent12345.test.invalid", ec2);
            EXPECT_GT(resolver.hit_count(), 0u);
            EXPECT_EQ(addrs.size(), addrs2.size());
            EXPECT_EQ(!!ec, !!ec2);
        }, [&](std::exception_ptr ep){ if(ep) std::rethrow_exception(ep); ioc.stop(); });
        ioc.run();
    }

    TEST(DnsDial, SessionDialViaDns)
    {
        net::io_context ioc;
        // echo server
        tcp::acceptor echo_ac(ioc, tcp::endpoint(tcp::v4(), 0));
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

        bool ok = false;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            network::target tgt;
            tgt.host = "127.0.0.1";
            tgt.port = std::to_string(echo_port);
            auto [code, tr] = co_await dial_with_dns(ioc.get_executor(), tgt);
            EXPECT_EQ(code, fault::code::success);
            if (!tr) { ADD_FAILURE() << "tr null"; co_return; }
            // 透传验证
            const std::string payload = "dns dial";
            std::error_code ec;
            co_await tr->async_write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(payload.data()), payload.size()), ec);
            EXPECT_FALSE(ec);
            std::array<std::byte, 64> buf{};
            auto n = co_await tr->async_read_some(buf, ec);
            EXPECT_FALSE(ec);
            std::string echo(reinterpret_cast<char*>(buf.data()), n);
            ok = (echo == payload);
            tr->close();
            boost::system::error_code ce;
            echo_ac.close(ce);
        }, [&](std::exception_ptr ep){ if(ep) std::rethrow_exception(ep); ioc.stop(); });
        ioc.run();
        EXPECT_TRUE(ok);
    }

} // namespace
