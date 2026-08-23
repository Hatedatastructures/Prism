/**
 * @file PadE2ETest.cpp
 * @brief Pad 中间件接入 session 管线验证
 * @details pad_transport 读取方向为纯透传、写入方向在载荷后追加随机填充，
 *          因此客户端收到的前 payload.size() 字节必为原文——据此对
 *          开关 pad 两种管线都做完整数据面断言。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include <common/core/fault/code.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/runtime/listener.hpp>
#include <common/core/runtime/session.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace preview;

    // 公共样板（run_coro/echo 上游见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::accept_echo_loop;
    using psm::testing::run_coro;
    using psm::testing::tcp_echo_server;

    /// 拨号上游（session_options::dial 回调实现；直连目标，不经 chain_state）
    auto dial_direct(net::any_io_executor ex, const network::target &t)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        std::error_code ec;
        network::dialer::dialer d(ex);
        auto up = co_await d.connect(
            std::string(t.host), static_cast<unsigned short>(std::stoi(std::string(t.port))), ec);
        if (ec || !up)
        {
            co_return std::pair{fault::code::unreachable, shared_transmission{}};
        }
        co_return std::pair{fault::code::success, std::move(up)};
    }

    /**
     * @brief 管线用例公共流程：echo 上游 + 单会话 listener + 客户端一次往返
     * @param pad pad 配置（nullptr = 不启用填充）
     * @return {是否拨号, 是否回环成功}
     */
    auto run_pipeline_case(net::io_context &ioc, const middleware::context::pad_config *pad)
        -> net::awaitable<std::pair<bool, bool>>
    {
        tcp::acceptor echo_ac(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_ac.local_endpoint().port();
        net::co_spawn(ioc.get_executor(), accept_echo_loop(echo_ac), net::detached);

        auto dialed = std::make_shared<bool>(false);
        auto make_accept_set_target =
            [echo_port](shared_transmission &, middleware::context &ctx) -> net::awaitable<fault::code>
        {
            ctx.target.host = "127.0.0.1";
            ctx.target.port = std::to_string(echo_port);
            co_return fault::code::success;
        };

        runtime::tcp_listener listener(ioc.get_executor(),
            [&](shared_transmission, std::size_t) -> std::shared_ptr<runtime::session>
            {
                runtime::session_options opts;
                opts.accept_protocol = make_accept_set_target;
                opts.pad = pad;
                opts.dial = [this_ex = ioc.get_executor(), dialed]
                    (const network::target &t) -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    *dialed = true;
                    co_return co_await dial_direct(this_ex, t);
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });

        bool ok = false;
        const auto rc = co_await listener.start(tcp::endpoint(tcp::v4(), 0));
        EXPECT_EQ(rc, fault::code::success);
        const auto lp = listener.local_endpoint().port();
        std::error_code ec;
        network::dialer::dialer d(ioc.get_executor());
        auto raw = co_await d.connect("127.0.0.1", lp, ec);
        if (!ec && raw)
        {
            const std::string payload = "pad pipeline case";
            co_await raw->async_write(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                           payload.size()),
                ec);
            std::array<std::byte, 64> buf{};
            std::size_t got = 0;
            while (!ec && got < payload.size())
            {
                const auto n = co_await raw->async_read_some(
                    std::span<std::byte>(buf).subspan(got), ec);
                if (n == 0) break;
                got += n;
            }
            // pad 开启时下行回环含补齐填充（≥ 载荷），前缀必为原文；
            // pad 关闭时回环恰为载荷长度
            ok = (got >= payload.size()) &&
                 std::equal(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(payload.size()),
                            reinterpret_cast<const std::byte *>(payload.data()));
            if (!ok)
            {
                ADD_FAILURE() << "DIAG got=" << got << " first16="
                              << std::string(reinterpret_cast<const char *>(buf.data()),
                                             (std::min)(got, std::size_t{24}));
            }
            raw->close();
        }
        listener.stop();
        boost::system::error_code ce;
        echo_ac.close(ce);
        co_return std::pair{*dialed, ok};
    }

    TEST(PadMiddleware, SessionWithoutPad)
    {
        net::io_context ioc;
        std::pair<bool, bool> result;
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            result = co_await run_pipeline_case(ioc, nullptr);
        });
        EXPECT_TRUE(result.first);
        EXPECT_TRUE(result.second);
    }

    TEST(PadMiddleware, SessionWithPadWrapsAndRelays)
    {
        net::io_context ioc;
        middleware::context::pad_config pad_cfg;
        pad_cfg.enabled = true;
        pad_cfg.min_size = 64;
        pad_cfg.max_size = 128;

        std::pair<bool, bool> result;
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            result = co_await run_pipeline_case(ioc, &pad_cfg);
        });
        EXPECT_TRUE(result.first);
        // 下行写入经 pad_transport 追加填充，但前缀字节仍是原文，回环必须成立
        EXPECT_TRUE(result.second);
    }

} // namespace
