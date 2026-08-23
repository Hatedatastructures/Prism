/**
 * @file MuxE2ETest.cpp
 * @brief Mux 中间件接入 session 管线验证
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <memory>
#include <string>

#include <common/core/fault/code.hpp>
#include <common/core/middleware/builtin/mux.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/runtime/listener.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/transmission.hpp>
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

    class mux_decorator final : public transmission
    {
    public:
        explicit mux_decorator(shared_transmission inner) : inner_(std::move(inner)) {}
        [[nodiscard]] auto executor() const -> executor_type override { return inner_->executor(); }
        [[nodiscard]] auto async_read_some(std::span<std::byte> b, std::error_code &ec) -> net::awaitable<std::size_t> override
        {
            co_return co_await inner_->async_read_some(b, ec);
        }
        [[nodiscard]] auto async_write_some(std::span<const std::byte> b, std::error_code &ec) -> net::awaitable<std::size_t> override
        {
            co_return co_await inner_->async_write_some(b, ec);
        }
        void close() override { inner_->close(); }
        void cancel() override { inner_->cancel(); }
        void shutdown() override { inner_->shutdown(); }
        void set_timeout(std::chrono::milliseconds ms) override { inner_->set_timeout(ms); }
        [[nodiscard]] auto is_open() const -> bool override { return inner_->is_open(); }
        [[nodiscard]] auto next_layer() noexcept -> transmission* override { return inner_.get(); }
        [[nodiscard]] auto next_layer() const noexcept -> const transmission* override { return inner_.get(); }
        bool wrapped{true};
    private:
        shared_transmission inner_;
    };

    struct fake_tx final : transmission
    {
        explicit fake_tx(net::any_io_executor ex) : ex_(ex) {}
        [[nodiscard]] auto executor() const -> executor_type override { return ex_; }
        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &ec) -> net::awaitable<std::size_t> override { ec.clear(); co_return 0; }
        [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &ec) -> net::awaitable<std::size_t> override { ec.clear(); co_return 0; }
        void close() override {}
        void cancel() override {}
        net::any_io_executor ex_;
    };

    TEST(MuxMiddleware, DirectWrapsInbound)
    {
        net::io_context ioc;
        bool ok = false;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto mem_in = std::make_shared<fake_tx>(ioc.get_executor());
            middleware::context ctx;
            shared_transmission inner = mem_in;
            middleware::builtin::mux_middleware mux_mw(
                [&](shared_transmission &in, middleware::context &) -> net::awaitable<bool>
                {
                    in = std::make_shared<mux_decorator>(std::move(in));
                    co_return true;
                });
            const auto ec = co_await mux_mw.handle(inner, ctx);
            EXPECT_EQ(ec, fault::code::success);
            auto dec = std::dynamic_pointer_cast<mux_decorator>(inner);
            ok = (dec && dec->wrapped);
        }, [&](std::exception_ptr ep){ if(ep) std::rethrow_exception(ep); ioc.stop(); });
        ioc.run();
        EXPECT_TRUE(ok);
    }

    TEST(MuxMiddleware, SessionWithMuxStillDialsAndRelays)
    {
        net::io_context ioc;
        tcp::acceptor echo_ac(ioc, tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = echo_ac.local_endpoint().port();
        net::co_spawn(ioc.get_executor(), accept_echo_loop(echo_ac), net::detached);

        bool mux_called = false;
        bool dialed = false;
        bool relay_ok = false;

        // 通过 accept_protocol 使 recognition 放宽，然后走 mux→dial→relay
        auto make_accept_set_target = [&](shared_transmission &inbound, middleware::context &ctx)
            -> net::awaitable<fault::code>
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
                opts.mux = [&](shared_transmission &inbound, middleware::context &) -> net::awaitable<bool>
                {
                    mux_called = true;
                    inbound = std::make_shared<mux_decorator>(std::move(inbound));
                    co_return true;
                };
                opts.dial = [&](const network::target &t) -> net::awaitable<std::pair<fault::code, shared_transmission>>
                {
                    dialed = true;
                    std::error_code ec;
                    network::dialer::dialer d(ioc.get_executor());
                    std::string host_str(t.host);
                    std::string port_str(t.port);
                    auto up = co_await d.connect(host_str, static_cast<unsigned short>(std::stoi(port_str)), ec);
                    if (ec || !up) co_return std::pair{fault::code::unreachable, shared_transmission{}};
                    co_return std::pair{fault::code::success, std::move(up)};
                };
                return std::make_shared<runtime::session>(std::move(opts));
            });

        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            const auto rc = co_await listener.start(tcp::endpoint(tcp::v4(), 0));
            EXPECT_EQ(rc, fault::code::success);
            const auto lp = listener.local_endpoint().port();
            std::error_code ec;
            network::dialer::dialer d(ioc.get_executor());
            auto raw = co_await d.connect("127.0.0.1", lp, ec);
            if (ec || !raw) co_return;
            const std::string payload = "mux relay";
            co_await raw->async_write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(payload.data()), payload.size()), ec);
            std::array<std::byte, 64> buf{};
            std::size_t got=0;
            while (!ec && got < payload.size())
            {
                auto n = co_await raw->async_read_some(std::span<std::byte>(buf).subspan(got), ec);
                if (n==0) break;
                got+=n;
            }
            relay_ok = (got==payload.size() && std::string(reinterpret_cast<char*>(buf.data()), got)==payload);
            raw->close();
            listener.stop();
            boost::system::error_code ce;
            echo_ac.close(ce);
        });
        EXPECT_TRUE(mux_called);
        EXPECT_TRUE(dialed);
        EXPECT_TRUE(relay_ok);
    }

} // namespace
