/**
 * @file ConfiguredMuxSessionScenarioTypes.hpp
 * @brief 配置化 Mux 单根场景的状态与传输 owner。
 */
#pragma once
#include <expected>

/** @file ConfiguredMuxSessionTest.cpp @brief configured SOCKS5 Smux 的正式根运行与真实 TCP 回显。 */
#include <Preview/Application/ProtocolAcceptors.hpp>
#include <Preview/Application/Configuration/GenerationBuilder.hpp>
#include <Preview/Application/Startup/GenerationPhase.hpp>
#include <Preview/Composition/Provider/ConfigurationCompiler.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Protocols/Vless/RequestCodec.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <Preview/Transport/Reliable.hpp>
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
    namespace Application = Preview::Application;
    namespace Provider = Preview::Composition::Provider;
    using Tcp = Net::ip::tcp;
    using FaultCode = Preview::Fault::Code;
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
              Bytes(std::make_shared<Preview::Memory::BytePool>(
                  Preview::Memory::BytePoolOptions{.BlockCount=8})),
              Acceptor(Executor, Tcp::endpoint(Net::ip::make_address("127.0.0.1"), 0)),
              Deadline(Executor), Done(Executor, 4), ClientReadPending(Executor, 1),
              BackendReceived(Executor, 1), FirstBackendDone(Executor, 1)
        {
            Family = FamilyValue;
            Kind = KindValue;
            BackendPort = Acceptor.local_endpoint().port();
            LoopbackBound = Acceptor.local_endpoint().address().is_loopback();
            auto [ClientValue, ServerValue] = Preview::MakeMemoryPair(Executor);
            Client = std::make_shared<Preview::MemoryStream>(std::move(ClientValue));
            Server = std::make_shared<Preview::MemoryStream>(std::move(ServerValue));
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
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
        Tcp::acceptor Acceptor;
        Net::steady_timer Deadline;
        Signal Done;
        Signal ClientReadPending;
        Signal BackendReceived;
        Signal FirstBackendDone;
        std::uint16_t BackendPort{0};
        Preview::SharedTransmission Client;
        Preview::SharedTransmission Server;
        std::shared_ptr<Preview::Contract::StreamEgress> Egress;
        std::shared_ptr<Preview::Contract::MuxSession> Root;
        std::weak_ptr<Preview::Contract::MuxSession> WeakRoot;
        std::shared_ptr<Preview::Contract::StreamFactory> Factory;
        std::shared_ptr<const Preview::Testing::ProviderAccounts> Directory;
        std::shared_ptr<Provider::BoundCatalog> Bound;
        std::shared_ptr<const Preview::Account::AccountBinding> Record;
        Preview::Contract::RequestMetadata Metadata;
        std::shared_ptr<Tcp::socket> BackendSocket;
        std::exception_ptr Failure;
        std::string FailureMessage;
        std::string ClientReadError;
        std::string SecondReadError;
        std::string FirstClientFinError;
        std::expected<void, Preview::Fault::Failure> RunStatus{std::unexpected(Preview::Fault::Failure{FaultCode::IoError})};
        Preview::AccountId AccountId{};
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
        bool WeakRootExpired{false};
        bool TimedOut{false};
    };

    class LocalEgress final : public Preview::Contract::StreamEgress
    {
    public:
        explicit LocalEgress(std::weak_ptr<ScenarioState> Owner) : Owner_(std::move(Owner)) {}

        auto Connect(Preview::Network::Target Target)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>> override
        {
            const auto Owner = Owner_.lock();
            if (!Owner)
            {
                co_return std::unexpected(Preview::Fault::Failure{FaultCode::Canceled});
            }
            ++Owner->Dials;
            const auto Port = Target.Port;
            if (Port == 0)
            {
                co_return std::unexpected(Preview::Fault::Failure{FaultCode::InvalidArgument});
            }

            Tcp::socket Socket(co_await Net::this_coro::executor);
            boost::system::error_code ConnectError;
            co_await Socket.async_connect(
                Tcp::endpoint(*Preview::Network::IpAddress(Target.Host), static_cast<std::uint16_t>(Port)),
                Net::redirect_error(Net::use_awaitable, ConnectError));
            if (ConnectError)
            {
                co_return std::unexpected(Preview::Fault::Failure{FaultCode::Unreachable});
            }
            co_return std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        }

    private:
        std::weak_ptr<ScenarioState> Owner_;
    };

    auto NotifyDone(const std::shared_ptr<ScenarioState> &State) -> void
    {
        (void)State->Done.try_send(boost::system::error_code{});
    }


} // namespace

