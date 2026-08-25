/**
 * @file MuxE2ETest.cpp
 * @brief Mux 中间件接入 Session 管线验证
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <memory>
#include <string>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Middleware/Builtin/Mux.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Middleware/Pipeline.hpp>
#include <common/Core/Net/Dialer/Dialer.hpp>
#include <common/Core/Runtime/Listener.hpp>
#include <common/Core/Runtime/Session.hpp>
#include <common/Core/Transmission.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using namespace Preview;

    // 公共样板（RunCoro/echo 上游见 <common/RuntimeTestHelpers.hpp>）
    using psm::testing::AcceptEchoLoop;
    using psm::testing::RunCoro;
    using psm::testing::tcp_echo_server;

    class mux_decorator final : public Transmission
    {
    public:
        explicit mux_decorator(SharedTransmission Inner) : inner_(std::move(Inner)) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return inner_->Executor(); }
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> b, std::error_code &ec) -> net::awaitable<std::size_t> override
        {
            co_return co_await inner_->AsyncReadSome(b, ec);
        }
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> b, std::error_code &ec) -> net::awaitable<std::size_t> override
        {
            co_return co_await inner_->AsyncWriteSome(b, ec);
        }
        void Close() override { inner_->Close(); }
        void Cancel() override { inner_->Cancel(); }
        void Shutdown() override { inner_->Shutdown(); }
        void SetTimeout(std::chrono::milliseconds ms) override { inner_->SetTimeout(ms); }
        [[nodiscard]] auto IsOpen() const -> bool override { return inner_->IsOpen(); }
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override { return inner_.get(); }
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission* override { return inner_.get(); }
        bool wrapped{true};
    private:
        SharedTransmission inner_;
    };

    struct fake_tx final : Transmission
    {
        explicit fake_tx(net::any_io_executor ex) : ex_(ex) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return ex_; }
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte>, std::error_code &ec) -> net::awaitable<std::size_t> override { ec.clear(); co_return 0; }
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte>, std::error_code &ec) -> net::awaitable<std::size_t> override { ec.clear(); co_return 0; }
        void Close() override {}
        void Cancel() override {}
        net::any_io_executor ex_;
    };

    TEST(MuxMiddleware, DirectWrapsInbound)
    {
        net::io_context ioc;
        bool Ok = false;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            auto mem_in = std::make_shared<fake_tx>(ioc.get_executor());
            Middleware::Context ctx;
            SharedTransmission Inner = mem_in;
            Middleware::Builtin::MuxMiddleware mux_mw(
                [&](SharedTransmission &in, Middleware::Context &) -> net::awaitable<bool>
                {
                    in = std::make_shared<mux_decorator>(std::move(in));
                    co_return true;
                });
            const auto ec = co_await mux_mw.Handle(Inner, ctx);
            EXPECT_EQ(ec, Fault::Code::success);
            auto dec = std::dynamic_pointer_cast<mux_decorator>(Inner);
            Ok = (dec && dec->wrapped);
        }, [&](std::exception_ptr ep){ if(ep) std::rethrow_exception(ep); ioc.stop(); });
        ioc.run();
        EXPECT_TRUE(Ok);
    }

    TEST(MuxMiddleware, SessionWithMuxStillDialsAndRelays)
    {
        net::io_context ioc;
        Tcp::acceptor echo_ac(ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_ac.local_endpoint().port();
        net::co_spawn(ioc.get_executor(), psm::testing::AcceptEchoLoop(echo_ac), net::detached);

        bool mux_called = false;
        bool dialed = false;
        bool relay_ok = false;

        // 通过 AcceptProtocol 使 recognition 放宽，然后走 mux→Dial→relay
        auto make_accept_set_target = [&](SharedTransmission &inbound, Middleware::Context &ctx)
            -> net::awaitable<Fault::Code>
        {
            ctx.Target.Host = "127.0.0.1";
            ctx.Target.Port = std::to_string(echo_port);
            co_return Fault::Code::success;
        };

        Runtime::TcpListener listener(ioc.get_executor(),
            [&](SharedTransmission, std::size_t) -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = make_accept_set_target;
                opts.mux = [&](SharedTransmission &inbound, Middleware::Context &) -> net::awaitable<bool>
                {
                    mux_called = true;
                    inbound = std::make_shared<mux_decorator>(std::move(inbound));
                    co_return true;
                };
                opts.Dial = [&](const Network::Target &t) -> net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    dialed = true;
                    std::error_code ec;
                    Network::Dialer::Dialer d(ioc.get_executor());
                    std::string host_str(t.Host);
                    std::string port_str(t.Port);
                    auto up = co_await d.Connect(host_str, static_cast<unsigned short>(std::stoi(port_str)), ec);
                    if (ec || !up) co_return std::pair{Fault::Code::unreachable, SharedTransmission{}};
                    co_return std::pair{Fault::Code::success, std::move(up)};
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        RunCoro(ioc, [&]() -> net::awaitable<void>
        {
            const auto rc = co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
            EXPECT_EQ(rc, Fault::Code::success);
            const auto lp = listener.LocalEndpoint().port();
            std::error_code ec;
            Network::Dialer::Dialer d(ioc.get_executor());
            auto raw = co_await d.Connect("127.0.0.1", lp, ec);
            if (ec || !raw) co_return;
            const std::string payload = "mux relay";
            co_await raw->AsyncWrite(std::span<const std::byte>(reinterpret_cast<const std::byte*>(payload.data()), payload.size()), ec);
            std::array<std::byte, 64> buf{};
            std::size_t got=0;
            while (!ec && got < payload.size())
            {
                auto n = co_await raw->AsyncReadSome(std::span<std::byte>(buf).subspan(got), ec);
                if (n==0) break;
                got+=n;
            }
            relay_ok = (got==payload.size() && std::string(reinterpret_cast<char*>(buf.data()), got)==payload);
            raw->Close();
            listener.Stop();
            boost::system::error_code ce;
            echo_ac.close(ce);
        });
        EXPECT_TRUE(mux_called);
        EXPECT_TRUE(dialed);
        EXPECT_TRUE(relay_ok);
    }

} // namespace
