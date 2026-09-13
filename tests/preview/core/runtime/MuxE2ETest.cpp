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

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Runtime/Middleware/Builtin/Mux.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Runtime/Middleware/Pipeline.hpp>
#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Runtime/Listener.hpp>
#include <preview/Runtime/Session.hpp>
#include <preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    namespace Network = Preview::Network;
    namespace Runtime = Preview::Runtime;
    using Tcp = Net::ip::tcp;
    using Preview::SharedTransmission;
    using Preview::Transmission;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Preview::Testing::AcceptEchoLoop;
    using Preview::Testing::RunCoro;
    using Preview::Testing::TcpEchoServer;

    class MuxDecorator final : public Transmission
    {
    public:
        explicit MuxDecorator(SharedTransmission Inner) : Inner_(std::move(Inner)) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Inner_->Executor(); }
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            co_return co_await Inner_->async_read_some(Buffer, ErrorCode);
        }
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            co_return co_await Inner_->async_write_some(Buffer, ErrorCode);
        }
        void Close() override { Inner_->Close(); }
        void Cancel() override { Inner_->Cancel(); }
        void Shutdown() override { Inner_->Shutdown(); }
        void SetTimeout(std::chrono::milliseconds ms) override { Inner_->SetTimeout(ms); }
        [[nodiscard]] auto IsOpen() const -> bool override { return Inner_->IsOpen(); }
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override { return Inner_.get(); }
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission* override { return Inner_.get(); }
        bool wrapped{true};
    private:
        SharedTransmission Inner_;
    };

    struct FakeTransport final : Transmission
    {
        explicit FakeTransport(Net::any_io_executor Executor) : Ex_(Executor) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Ex_; }
        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override { ErrorCode.clear(); co_return 0; }
        [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override { ErrorCode.clear(); co_return 0; }
        void Close() override {}
        void Cancel() override {}
        Net::any_io_executor Ex_;
    };

    TEST(MuxMiddleware, DirectWrapsInbound)
    {
        Net::io_context ioc;
        bool Ok = false;
        Net::co_spawn(ioc, [&]() -> Net::awaitable<void>
        {
            auto MemoryInbound = std::make_shared<FakeTransport>(ioc.get_executor());
            Middleware::Context Context;
            SharedTransmission Inner = MemoryInbound;
            Middleware::Builtin::MuxMiddleware MuxMiddleware(
                [&](SharedTransmission &in, Middleware::Context &) -> Net::awaitable<bool>
                {
                    in = std::make_shared<MuxDecorator>(std::move(in));
                    co_return true;
                });
            const auto ErrorCode = co_await MuxMiddleware.Handle(Inner, Context);
            EXPECT_EQ(ErrorCode, Fault::Code::Success);
            auto Decorator = std::dynamic_pointer_cast<MuxDecorator>(Inner);
            Ok = Decorator && Decorator->wrapped;
        }, [&](std::exception_ptr ep){ if(ep) std::rethrow_exception(ep); ioc.stop(); });
        ioc.run();
        EXPECT_TRUE(Ok);
    }

    TEST(MuxMiddleware, SessionWithMuxStillDialsAndRelays)
    {
        Net::io_context ioc;
        Tcp::acceptor echo_ac(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto echo_port = echo_ac.local_endpoint().port();
        Net::co_spawn(ioc.get_executor(), Preview::Testing::AcceptEchoLoop(echo_ac), Net::detached);

        bool mux_called = false;
        bool dialed = false;
        bool relay_ok = false;

        // 通过 AcceptProtocol 使 recognition 放宽，然后走 mux→Dial→relay
        auto MakeAcceptSetTarget = [&](SharedTransmission &, Middleware::Context &Context)
            -> Net::awaitable<Fault::Code>
        {
            Context.Target.Host = "127.0.0.1";
            Context.Target.Port = std::to_string(echo_port);
            co_return Fault::Code::Success;
        };

        Runtime::TcpListener listener(ioc.get_executor(),
            [&](SharedTransmission, std::size_t) -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions opts;
                opts.AcceptProtocol = MakeAcceptSetTarget;
                opts.mux = [&](SharedTransmission &Inbound, Middleware::Context &) -> Net::awaitable<bool>
                {
                    mux_called = true;
                    Inbound = std::make_shared<MuxDecorator>(std::move(Inbound));
                    co_return true;
                };
                opts.Dial = [&](const Network::Target &t) -> Net::awaitable<std::pair<Fault::Code, SharedTransmission>>
                {
                    dialed = true;
                    std::error_code ec;
                    Network::Dialer::Dialer d(ioc.get_executor());
                    std::string host_str(t.Host);
                    std::string port_str(t.Port);
                    auto up = co_await d.Connect(host_str, static_cast<unsigned short>(std::stoi(port_str)), ec);
                    if (ec || !up) co_return std::pair{Fault::Code::Unreachable, SharedTransmission{}};
                    co_return std::pair{Fault::Code::Success, std::move(up)};
                };
                return std::make_shared<Runtime::Session>(std::move(opts));
            });

        RunCoro(ioc, [&]() -> Net::awaitable<void>
        {
            const auto rc = co_await listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
            EXPECT_EQ(rc, Fault::Code::Success);
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
                auto n = co_await raw->async_read_some(std::span<std::byte>(buf).subspan(got), ec);
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
