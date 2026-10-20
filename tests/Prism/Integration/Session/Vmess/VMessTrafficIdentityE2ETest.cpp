/**
 * @file VMessTrafficIdentityE2ETest.cpp
 * @brief 验证 VMess TCP 真实链路完成后的流量身份事件。
 */

#include "VMessTcpE2ETestSupport.hpp"

#include <Prism/Runtime/SessionAdmissionTestSupport.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

#include <boost/asio/io_context.hpp>

#include <array>
#include <cstddef>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <utility>

namespace
{

    namespace Net = boost::asio;
    namespace Runtime = Prism::Runtime;
    namespace Vmess = Prism::Vmess;
    namespace Fault = Prism::Fault;
    namespace VmessSupport = Prism::Testing::VmessTcpE2E;
    using VmessSupport::CloseVmessConnection;
    using VmessSupport::FinishVmessTcpFlow;
    using VmessSupport::StartVmessListener;
    using VmessSupport::TestUuid;
    using VmessSupport::VmessSessionFactory;
    using VmessSupport::VmessTcpEchoOwner;
    using VmessSupport::vmess_chain_state;

    struct VmessTrafficFlow final
    {
        Net::io_context &Ioc;
        Runtime::TcpListener &Listener;
        VmessTcpEchoOwner &Echo;
    };

    /** @brief 驱动 VMess 业务字节并等待 listener registry 的真实终结。 */
    auto RunVmessTrafficFlow(VmessTrafficFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstFailure;
        std::shared_ptr<Vmess::Conn<>> Proxy;
        try
        {
            if (co_await StartVmessListener(Flow.Listener))
            {
                auto Raw = co_await VmessSupport::DialVmessListener(Flow.Ioc, Flow.Listener);
                if (Raw)
                {
                    const auto ClientConfig = Vmess::ClientConfig{TestUuid()};
                    const auto Target = Vmess::Address{
                        Vmess::AddressType::Domain, "example.com", 80};
                    auto ProtocolConnect = co_await Vmess::Connect(
                        Vmess::ConnectParameters{
                            std::move(*Raw), ClientConfig, Target, Vmess::Command::Tcp});
                    if (!ProtocolConnect)
                    {
                        ADD_FAILURE() << "Unexpected protocol handshake failure: "
                            << Prism::Fault::Describe(ProtocolConnect.error().Code)
                            << " Native=" << ProtocolConnect.error().Native.category().name()
                            << ":" << ProtocolConnect.error().Native.value();
                    }
                    else if (!*ProtocolConnect)
                    {
                        ADD_FAILURE() << "Protocol Connect succeeded without a connection owner";
                    }
                    else
                    {
                        Proxy = std::move(*ProtocolConnect);
                    }
                    if (Proxy)
                    {
                        const std::string Payload = "traffic identity Probe";
                        const auto Write = co_await Proxy->WriteExact(std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
                        auto IoFailure = Write.Failure;
                        if (!IoFailure.Failed() && Write.Bytes != Payload.size())
                        {
                            IoFailure = {Fault::Code::IoError};
                        }
                        std::array<std::byte, 64> Buffer{};
                        std::size_t Received = 0;
                        while (!IoFailure.Failed() && Received < Payload.size())
                        {
                            const auto Read = co_await Proxy->ReadSome(
                                std::span<std::byte>(Buffer).subspan(Received));
                            const auto Remaining = Payload.size() - Received;
                            if (Read.Bytes > Remaining)
                            {
                                IoFailure = {Fault::Code::InvalidArgument, Read.Failure.Native};
                                break;
                            }
                            Received += Read.Bytes;
                            if (Read.Failure.Failed())
                            {
                                IoFailure = Read.Failure;
                                break;
                            }
                            if (Read.Bytes == 0U)
                            {
                                IoFailure = {Fault::Code::Eof};
                                break;
                            }
                        }
                        EXPECT_FALSE(IoFailure.Failed());
                        EXPECT_EQ(Received, Payload.size());
                        EXPECT_EQ(std::string(
                                      reinterpret_cast<const char *>(Buffer.data()), Received),
                                  Payload);
                    }
                }
            }
        }
        catch (...)
        {
            FirstFailure = std::current_exception();
        }
        CloseVmessConnection(Proxy, FirstFailure);
        co_await FinishVmessTcpFlow(Flow.Echo, Flow.Listener, FirstFailure);
    }

    TEST(TcpListener, VmessTrafficIdentity)
    {
        Net::io_context ioc;
        auto Echo = VmessSupport::StartVmessTcpEcho(ioc);
        const auto echo_port = Echo.Acceptor->local_endpoint().port();
        auto StateObj = std::make_shared<vmess_chain_state>(
            vmess_chain_state{ioc.get_executor(), echo_port});

        auto recorder = std::make_shared<Prism::Testing::TrafficRecorder>();


        Runtime::TcpListener listen(
            Runtime::TcpListener::Options{
            .Executor = ioc.get_executor(),
            .Factory = VmessSessionFactory{
                StateObj, Vmess::ServerConfig{TestUuid()}, {}, recorder},
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{5})});

        Prism::Testing::RunCoro(ioc, RunVmessTrafficFlow(
            VmessTrafficFlow{ioc, listen, Echo}));
        EXPECT_EQ(recorder->LastEvent.Kind, Prism::Foundation::TrafficEventKind::Completed);
        EXPECT_EQ(recorder->LastEvent.Account, Prism::AccountId{1});
        EXPECT_EQ(recorder->Calls, 1);
        EXPECT_GT(recorder->Up, 0u);
        EXPECT_GT(recorder->Down, 0u);
        EXPECT_FALSE(*Echo.Failure);
    }

} // namespace
