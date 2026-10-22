/**
 * @file VlessUpstreamAbortE2ETest.cpp
 * @brief VLESS 上游立即关闭后的 TCP 关闭合同。
 */

#include <gtest/gtest.h>
#include <Test/Prism/Runtime/Session/SessionAdmissionSupport.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <array>
#include <exception>
#include <memory>

#include "VlessTestSupport.hpp"

namespace
{
    namespace Net = boost::asio;
    namespace Runtime = Prism::Runtime;
    namespace Vless = Prism::Vless;
    using Prism::SharedTransmission;
    namespace VlessTest = Prism::Testing::VlessE2E;
    using VlessTest::CloseVlessTransmission;
    using VlessTest::ConnectVlessWithTestUuid;
    using VlessTest::DialVlessListener;
    using VlessTest::FinishVlessListener;
    using VlessTest::StartVlessListener;
    using VlessTest::TestUuid;
    using VlessTest::VlessChainState;
    using VlessTest::VlessSessionFactory;
    using Tcp = Net::ip::tcp;

    struct VlessUpstreamAbortFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        Tcp::acceptor &UpstreamAcceptor;
        bool &SawClose;
    };

    /** @brief 驱动 VLESS 上游立即关闭后的 TCP EOF 收口场景。 */
    auto RunVlessUpstreamAbortFlow(VlessUpstreamAbortFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        SharedTransmission Proxy;
        try
        {
            if (co_await StartVlessListener(Flow.Listener))
            {
                auto Raw = co_await DialVlessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    auto ConnectResult = co_await ConnectVlessWithTestUuid(
                        std::move(*Raw),
                        Vless::Address{Vless::AddressType::Domain, "example.com", 80});
                    if (!ConnectResult)
                    {
                        ADD_FAILURE() << "VLESS upstream-abort handshake failed: "
                            << Prism::Fault::Describe(ConnectResult.error().Code)
                            << " Native=" << ConnectResult.error().Native.category().name()
                            << ":" << ConnectResult.error().Native.value();
                    }
                    else if (!*ConnectResult)
                    {
                        ADD_FAILURE() << "VLESS factory returned an empty successful owner";
                    }
                    else
                    {
                        Proxy = std::move(*ConnectResult);
                    }
                    if (Proxy)
                    {
                        std::array<std::byte, 8> Buffer{};
                        const auto Read = co_await Proxy->ReadSome(Buffer);
                        Flow.SawClose = Read.Bytes == 0U || Read.Failure.Failed();
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVlessTransmission(Proxy, FirstFailure);
        boost::system::error_code CloseError;
        Flow.UpstreamAcceptor.close(CloseError);
        co_await FinishVlessListener(Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, VlessTcpConnectUpstreamAbort)
    {
        Net::io_context Ioc;
        Tcp::acceptor UpstreamAcceptor(Ioc, Tcp::endpoint(Tcp::v4(), 0));
        const auto UpstreamPort = UpstreamAcceptor.local_endpoint().port();
        auto ChainState = std::make_shared<VlessChainState>(
            VlessChainState{Ioc.get_executor(), UpstreamPort});
        auto UpstreamFailure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            Ioc.get_executor(), Prism::Testing::AcceptAndClose(UpstreamAcceptor),
            [UpstreamFailure](const std::exception_ptr &Error)
            {
                if (Error)
                {
                    *UpstreamFailure = Error;
                }
            });
        Runtime::TcpListener Listener(
            Runtime::TcpListener::Options{
                .Executor = Ioc.get_executor(),
                .Factory = VlessSessionFactory{
                    ChainState, Vless::ServerConfig{TestUuid()}},
                .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                    Prism::GenerationId{1})});

        bool SawClose = false;
        Prism::Testing::RunCoro(Ioc, RunVlessUpstreamAbortFlow(
            VlessUpstreamAbortFlow{Ioc, Listener, UpstreamAcceptor, SawClose}));
        EXPECT_TRUE(SawClose);
        EXPECT_FALSE(*UpstreamFailure);
    }
}
