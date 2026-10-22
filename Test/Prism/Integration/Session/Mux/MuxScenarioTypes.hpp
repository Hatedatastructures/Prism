/**
 * @file MuxScenarioTypes.hpp
 * @brief 配置化 Mux 单根场景的状态与传输 owner。
 */
#pragma once
#include <expected>

/** @file ConfiguredMuxSessionTest.cpp @brief configured SOCKS5 Smux 的正式根运行与真实 TCP 回显。 */
#include <Prism/Application/ProtocolAcceptors.hpp>
#include <Prism/Application/Configuration/GenerationBuilder.hpp>
#include <Prism/Application/Startup/GenerationPhase.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Prism/GenerationPublication.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    namespace Application = Prism::Application;
    namespace Provider = Prism::Composition::Provider;
    using Tcp = Net::ip::tcp;
    using FaultCode = Prism::Fault::Code;
    using Signal = Net::experimental::channel<void(boost::system::error_code)>;

    constexpr std::string_view Payload{"P4-S5-REAL-MUX-ECHO"};
    constexpr std::string_view Continuation{"P4-MAX1-CONTINUATION"};
    constexpr std::string_view ReplacementPayload{"P4-FIN-REPLACEMENT"};

    enum class ProtocolFamily
    {
        Socks5,
        Ss2022,
    };

    enum class ScenarioKind
    {
        Echo,
        CancelPending,
        QuotaSecond,
        Replacement,
    };

    auto ProtocolName(const ProtocolFamily Family) -> std::string_view
    {
        return Family == ProtocolFamily::Socks5 ? "socks5" : "ss2022";
    }

    struct ScenarioState final
    {
        ScenarioState(const ProtocolFamily FamilyValue, const ScenarioKind KindValue)
            : Executor(Io.get_executor()),
              Bytes(std::make_shared<Prism::Memory::BytePool>(
                  Prism::Memory::BytePoolOptions{.BlockCount=8})),
              Acceptor(Executor, Tcp::endpoint(Net::ip::make_address("127.0.0.1"), 0)),
              Deadline(Executor), Done(Executor, 4), ClientReadPending(Executor, 1),
              BackendReceived(Executor, 1), FirstBackendDone(Executor, 1)
        {
            Family = FamilyValue;
            Kind = KindValue;
            BackendPort = Acceptor.local_endpoint().port();
            LoopbackBound = Acceptor.local_endpoint().address().is_loopback();
            auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Executor);
            Client = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
            Server = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
        }

        auto Stop() noexcept -> void
        {
            if (StopRequested) return;
            StopRequested = true;
            if (Root)
            {
                Root->Close();
            }
            if (Client)
            {
                (void)Client->Close();
            }
            if (Server)
            {
                (void)Server->Close();
            }
            if (BackendSocket)
            {
                boost::system::error_code SocketError;
                BackendSocket->cancel(SocketError);
                BackendSocket->close(SocketError);
            }
            boost::system::error_code Error;
            Acceptor.close(Error);
            Deadline.cancel();
            (void)ClientReadPending.try_send(Error);
            (void)BackendReceived.try_send(Error);
            (void)FirstBackendDone.try_send(Error);
        }

        Net::io_context Io;
        ProtocolFamily Family{ProtocolFamily::Socks5};
        ScenarioKind Kind{ScenarioKind::Echo};
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        Tcp::acceptor Acceptor;
        Net::steady_timer Deadline;
        Signal Done;
        Signal ClientReadPending;
        Signal BackendReceived;
        Signal FirstBackendDone;
        std::uint16_t BackendPort{0};
        Prism::SharedTransmission Client;
        Prism::SharedTransmission Server;
        std::shared_ptr<Prism::Contract::StreamEgress> Egress;
        std::shared_ptr<Prism::Contract::MuxSession> Root;
        std::weak_ptr<Prism::Contract::MuxSession> WeakRoot;
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
        std::shared_ptr<const Prism::Testing::ProviderAccounts> Directory;
        std::shared_ptr<Prism::Runtime::GenerationPublication> AdmissionPublication;
        std::shared_ptr<Provider::BoundCatalog> Bound;
        std::shared_ptr<const Prism::Account::AccountBinding> Record;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        Prism::Contract::RequestMetadata Metadata;
        std::shared_ptr<Tcp::socket> BackendSocket;
        std::exception_ptr Failure;
        std::string FailureMessage;
        std::string ClientReadError;
        std::string SecondReadError;
        std::string FirstClientFinError;
        std::expected<void, Prism::Fault::Failure> RunStatus{std::unexpected(Prism::Fault::Failure{FaultCode::IoError})};
        Prism::AccountId AccountId{};
        std::size_t Dials{0};
        std::size_t BackendBytes{0};
        std::size_t BackendContinuationBytes{0};
        std::size_t BackendTailBytes{0};
        std::size_t ReplacementBackendBytes{0};
        std::size_t ReplacementTailBytes{0};
        std::size_t FirstClientFinCount{0};
        std::size_t ClientReadCount{0};
        std::size_t SecondReadCount{0};
        bool Authenticated{false};
        bool LeaseValid{false};
        bool PlaneMux{false};
        bool SameRecord{false};
        bool CountersAtEcho{false};
        bool CountersDrained{false};
        bool BackendAccepted{false};
        bool BackendReceivedPayload{false};
        bool BackendContinuationReceived{false};
        bool BackendContinuationEchoed{false};
        bool ContinuationEchoed{false};
        bool BackendOpenAtContinuation{false};
        bool FirstBackendClosed{false};
        bool FirstBackendPeerClosed{false};
        bool FirstClientFinReturned{false};
        bool FirstLeaseReleased{false};
        bool CountersAtReplacementEcho{false};
        bool ReplacementOpened{false};
        bool ReplacementBackendReceived{false};
        bool ReplacementEchoed{false};
        bool ReplacementBackendPeerClosed{false};
        bool ClientReadPendingSignaled{false};
        bool ClientReadReturned{false};
        bool PreCancelCounters{false};
        bool SecondOpened{false};
        bool SecondRejected{false};
        bool FirstStillActiveAtReject{false};
        bool SecondReadReturned{false};
        std::uint8_t SecondStatus{0xff};
        bool LoopbackBound{false};
        bool StopRequested{false};
        bool BackendEchoed{false};
        bool BackendClosed{false};
        bool BackendPeerClosed{false};
        bool BackendReturned{false};
        bool ClientClosed{false};
        bool ClientReturned{false};
        bool ServerReturned{false};
        bool RunReturned{false};
        bool CatalogDrained{false};
        std::size_t GenerationUsesAfterDrain{0};
        bool WeakRootExpired{false};
        bool TimedOut{false};
    };

    class LocalEgress final : public Prism::Contract::StreamEgress
    {
    public:
        explicit LocalEgress(std::weak_ptr<ScenarioState> Owner) : Owner_(std::move(Owner)) {}

        auto Connect(Prism::Network::Target Target)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>> override
        {
            const auto Owner = Owner_.lock();
            if (!Owner)
            {
                co_return std::unexpected(Prism::Fault::Failure{FaultCode::Canceled});
            }
            ++Owner->Dials;
            const auto Port = Target.Port;
            if (Port == 0)
            {
                co_return std::unexpected(Prism::Fault::Failure{FaultCode::InvalidArgument});
            }

            Tcp::socket Socket(co_await Net::this_coro::executor);
            boost::system::error_code ConnectError;
            co_await Socket.async_connect(
                Tcp::endpoint(*Prism::Network::IpAddress(Target.Host), static_cast<std::uint16_t>(Port)),
                Net::redirect_error(Net::use_awaitable, ConnectError));
            if (ConnectError)
            {
                co_return std::unexpected(Prism::Fault::Failure{FaultCode::Unreachable});
            }
            co_return std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        }

    private:
        std::weak_ptr<ScenarioState> Owner_;
    };

    auto NotifyDone(const std::shared_ptr<ScenarioState> &State) -> void
    {
        (void)State->Done.try_send(boost::system::error_code{});
    }


} // namespace
