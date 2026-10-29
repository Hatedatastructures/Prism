/**
 * @file MultiRootTypes.hpp
 * @brief 配置化 Mux 双 root 场景的状态与 egress owner.
 */
#pragma once

#include "ScenarioTypes.hpp"
#include <expected>
#include <Prism/Foundation/Memory/BytePool.hpp>

namespace
{
    constexpr std::array<std::string_view, 2> MultiRootPayloads{
        "P4-MULTI-ROOT-FIRST", "P4-MULTI-ROOT-SECOND"};

    struct MultiRootState final
    {
        explicit MultiRootState(const ProtocolFamily FamilyValue)
            : Family(FamilyValue), Executor(Io.get_executor()),
              Bytes{std::make_shared<Prism::Memory::BytePool>(
                        Prism::Memory::BytePoolOptions{.BlockCount=8}),
                    std::make_shared<Prism::Memory::BytePool>(
                        Prism::Memory::BytePoolOptions{.BlockCount=8})},
              Deadline(Executor), RootReady(Executor, 2), BackendReady(Executor, 2),
              FirstEcho(Executor, 1), SecondPending(Executor, 1), FirstCloseRequest(Executor, 1),
              FirstClientClosed(Executor, 1), FirstBackendEof(Executor, 1),
              SecondEchoGate(Executor, 1), SecondEcho(Executor, 1), RootDone(Executor, 2),
              BackendDone(Executor, 2), ClientFinished(Executor, 2),
              DrainEntered(Executor, 2), DrainDone(Executor, 2), TasksDone(Executor, 8)
        {
            LoopbackBound = true;
            for (std::size_t Index = 0; Index < BackendAcceptor.size(); ++Index)
            {
                BackendAcceptor[Index] = std::make_shared<Tcp::acceptor>(
                    Executor, Tcp::endpoint(Net::ip::make_address("127.0.0.1"), 0));
                BackendPort[Index] = BackendAcceptor[Index]->local_endpoint().port();
                LoopbackBound = LoopbackBound && BackendAcceptor[Index]->local_endpoint().address().is_loopback();
            }
            for (std::size_t Index = 0; Index < Client.size(); ++Index)
            {
                auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Executor);
                Client[Index] = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
                Server[Index] = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
            }
        }

        auto DebugState(const char *Event) noexcept -> void
        {
            auto FamilyLabel = "ss2022";
            if (Family == ProtocolFamily::Socks5)
            {
                FamilyLabel = "socks5";
            }
            std::fprintf(stderr,
                "[ConfiguredMuxSession] event=%s family=%s failure=%s coordinator=%s "
                "backend0=%s backend1=%s server0=%s server1=%s client0=%s client1=%s\n",
                Event, FamilyLabel,
                FailureMessage.c_str(), CoordinatorStage.c_str(), BackendStage[0].c_str(),
                BackendStage[1].c_str(), ServerStage[0].c_str(), ServerStage[1].c_str(),
                ClientStage[0].c_str(), ClientStage[1].c_str());
            std::fflush(stderr);
        }

        auto Stop(const char *Origin = "unspecified") noexcept -> void
        {
            if (StopRequested) return;
            StopRequested = true;
            if (!StopLogged)
            {
                StopLogged = true;
                DebugState(Origin);
            }
            for (const auto &Value : Root)
            {
                if (Value)
                {
                    Value->Close();
                }
            }
            for (const auto &Value : Client)
            {
                if (Value)
                {
                    (void)Value->Close();
                }
            }
            for (const auto &Value : Server)
            {
                if (Value)
                {
                    (void)Value->Close();
                }
            }
            for (const auto &Value : BackendSocket)
            {
                if (Value)
                {
                    boost::system::error_code Error;
                    Value->cancel(Error);
                    Value->close(Error);
                }
            }
            for (const auto &Value : BackendAcceptor)
            {
                if (Value)
                {
                    boost::system::error_code Error;
                    Value->close(Error);
                }
            }
            boost::system::error_code Error;
            Deadline.cancel();
            (void)RootReady.try_send(Error);
            (void)RootReady.try_send(Error);
            (void)BackendReady.try_send(Error);
            (void)BackendReady.try_send(Error);
            (void)FirstEcho.try_send(Error);
            (void)SecondPending.try_send(Error);
            (void)FirstCloseRequest.try_send(Error);
            (void)FirstClientClosed.try_send(Error);
            (void)FirstBackendEof.try_send(Error);
            (void)SecondEchoGate.try_send(Error);
            (void)SecondEcho.try_send(Error);
            (void)RootDone.try_send(Error);
            (void)RootDone.try_send(Error);
            (void)BackendDone.try_send(Error);
            (void)BackendDone.try_send(Error);
            (void)ClientFinished.try_send(Error);
            (void)ClientFinished.try_send(Error);
            (void)DrainEntered.try_send(Error);
            (void)DrainEntered.try_send(Error);
            (void)DrainDone.try_send(Error);
            (void)DrainDone.try_send(Error);
        }

        Net::io_context Io;
        ProtocolFamily Family;
        Net::any_io_executor Executor;
        std::array<std::shared_ptr<Prism::Memory::BytePool>, 2> Bytes;
        Net::steady_timer Deadline;
        Signal RootReady;
        Signal BackendReady;
        Signal FirstEcho;
        Signal SecondPending;
        Signal FirstCloseRequest;
        Signal FirstClientClosed;
        Signal FirstBackendEof;
        Signal SecondEchoGate;
        Signal SecondEcho;
        Signal RootDone;
        Signal BackendDone;
        Signal ClientFinished;
        Signal DrainEntered;
        Signal DrainDone;
        Signal TasksDone;
        std::array<Prism::SharedTransmission, 2> Client;
        std::array<Prism::SharedTransmission, 2> Server;
        std::array<std::shared_ptr<Tcp::acceptor>, 2> BackendAcceptor;
        std::array<std::shared_ptr<Prism::Contract::StreamFactory>, 2> Factory;
        std::array<std::shared_ptr<Prism::Mux::RootBinding>, 2> RootBinding;
        std::array<std::shared_ptr<Prism::Contract::MuxSession>, 2> Root;
        std::array<std::weak_ptr<Prism::Contract::MuxSession>, 2> WeakRoot;
        std::array<std::shared_ptr<Prism::Mux::Smux::Client<>>, 2> ClientMux;
        std::array<Prism::SharedTransmission, 2> Child;
        std::array<std::shared_ptr<Tcp::socket>, 2> BackendSocket;
        std::array<std::expected<void, Prism::Fault::Failure>, 2> RunStatus{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError}),
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError})};
        std::array<std::size_t, 2> BackendBytes{};
        std::array<std::size_t, 2> BackendTailBytes{};
        std::array<bool, 2> Authenticated{};
        std::array<bool, 2> LeaseValid{};
        std::array<bool, 2> BackendReceived{};
        std::array<bool, 2> BackendClosed{};
        std::array<bool, 2> BackendPeerClosed{};
        std::array<bool, 2> RootReturned{};
        std::array<bool, 2> ClientDone{};
        std::array<bool, 2> ClientReadReturned{};
        bool CatalogDrained{false};
        Prism::Fault::Failure CatalogDrainFailure{};
        std::array<bool, 2> DrainSucceeded{};
        std::array<bool, 2> DrainFailed{};
        std::array<Prism::Fault::Failure, 2> DrainFailure{};
        std::shared_ptr<Prism::Contract::StreamEgress> Egress;
        std::shared_ptr<Prism::Runtime::GenerationPublication> AdmissionPublication;
        std::shared_ptr<Provider::BoundCatalog> Bound;
        std::shared_ptr<const Prism::Testing::ProviderAccounts> Directory;
        std::shared_ptr<const Prism::Account::AccountBinding> Record;
        Prism::Foundation::GenerationPin Pin;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> WeakGeneration;
        std::weak_ptr<const Prism::Account::AccountBinding> WeakRecord;
        std::exception_ptr Failure;
        std::string SetupError;
        std::string FailureMessage;
        std::string CoordinatorStage;
        std::array<std::string, 2> BackendStage;
        std::array<std::string, 2> ServerStage;
        std::array<std::string, 2> ClientStage;
        std::array<std::string, 2> BackendTailError;
        std::array<std::uint16_t, 2> BackendPort{};
        std::size_t Dials{0};
        std::size_t ConnectionsBeforeClose{0};
        std::size_t StreamsBeforeClose{0};
        std::size_t ConnectionsAfterFirstClose{0};
        std::size_t StreamsAfterFirstClose{0};
        std::size_t ConnectionsAfterDrain{0};
        std::size_t StreamsAfterDrain{0};
        bool LoopbackBound{false};
        bool NoColdAuthentication{false};
        bool DistinctFactories{false};
        bool DistinctRootBindings{false};
        bool FirstEchoed{false};
        bool SecondPayloadEchoed{false};
        bool SecondBackendEchoed{false};
        bool SecondPendingSignaled{false};
        bool FirstRootClosedSiblingActive{false};
        bool TimedOut{false};
        bool StopLogged{false};
        bool StopRequested{false};
        std::size_t TasksStarted{0};
        std::size_t TasksCompleted{0};
    };

    class MultiRootEgress final : public Prism::Contract::StreamEgress
    {
    public:
        explicit MultiRootEgress(std::weak_ptr<MultiRootState> Owner) : Owner_(std::move(Owner)) {}

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
        std::weak_ptr<MultiRootState> Owner_;
    };


} // namespace
