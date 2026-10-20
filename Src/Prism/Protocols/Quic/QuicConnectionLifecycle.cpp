/**
 * @file QuicConnectionLifecycle.cpp
 * @brief 单条 QUIC connection 的关闭、排空和真实退休实现。
 */
#include <Prism/Protocols/Quic/QuicConnectionLifecycle.hpp>

#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <exception>
#include <utility>

namespace Prism::Protocols
{

    QuicConnectionLifecycle::QuicConnectionLifecycle(QuicConnectionPreparation Input)
        : Listener_(std::move(Input.Listener)),
          NativeTls_(Listener_.Tls),
          Peer_(Input.Request.Peer),
          Observer_(std::move(Input.Request.OnClosed)),
          Metadata_(std::move(Input.Request.Metadata)),
          Traffic_(std::move(Input.Traffic)),
          Lifetime_(Input.Lifetime),
          Generation_(std::move(Input.Generation)),
          GenerationUse_(std::move(Input.Request.GenerationUse)),
          Context_(Prism::Executor::ContextOwner::Find(Listener_.Executor)),
          Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(Listener_.Executor)),
          Barrier_(Reclaimer_)
    {
        (void)Barrier_.Enter();
    }

    QuicConnectionLifecycle::~QuicConnectionLifecycle() = default;

    auto QuicConnectionLifecycle::Start() -> void
    {
        if (Server_)
        {
            Server_->Start();
        }
    }

    [[nodiscard]] auto QuicConnectionLifecycle::ReceivePacket(
        const std::span<const std::byte> Payload,
        const boost::asio::ip::udp::endpoint& Peer) -> bool
    {
        return Server_ && Server_->ReceivePacket(Payload, Peer);
    }

    [[nodiscard]] auto QuicConnectionLifecycle::State() const noexcept
        -> Prism::Contract::QuicConnectionState
    {
        if (!Server_)
        {
            return {false, true};
        }
        const auto Health = Server_->Health();
        return {Health.HandshakeReady, Health.Closed};
    }

    [[nodiscard]] auto QuicConnectionLifecycle::RequestClose() noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        auto State = CloseRequest_.load(std::memory_order_acquire);
        while (true)
        {
            if (State == CloseRequestState::Failed)
            {
                return std::unexpected(Failure_.Load());
            }
            if (State == CloseRequestState::Queued ||
                State == CloseRequestState::Finalizing ||
                State == CloseRequestState::Completed)
            {
                return {};
            }
            if (State == CloseRequestState::Submitting)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }

            const auto Self = weak_from_this().lock();
            if (!Self)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            if (!CanDispatch())
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            if (!CloseRequest_.compare_exchange_weak(
                    State, CloseRequestState::Submitting,
                    std::memory_order_acq_rel, std::memory_order_acquire))
            {
                continue;
            }

            const auto Posted = Reclaimer_->Post([Self] { Self->StartFinalizer(); });
            if (!Posted)
            {
                auto Submitting = CloseRequestState::Submitting;
                if (CloseRequest_.compare_exchange_strong(
                        Submitting, CloseRequestState::Open,
                        std::memory_order_acq_rel))
                {
                    return std::unexpected(Posted.error());
                }
                const auto Current = CloseRequest_.load(std::memory_order_acquire);
                if (Current == CloseRequestState::Failed)
                {
                    return std::unexpected(Failure_.Load());
                }
                if (Current == CloseRequestState::Queued ||
                    Current == CloseRequestState::Finalizing ||
                    Current == CloseRequestState::Completed)
                {
                    return {};
                }
                return std::unexpected(Posted.error());
            }

            auto Submitting = CloseRequestState::Submitting;
            if (CloseRequest_.compare_exchange_strong(
                    Submitting, CloseRequestState::Queued,
                    std::memory_order_acq_rel))
            {
                return {};
            }
            const auto Current = CloseRequest_.load(std::memory_order_acquire);
            if (Current == CloseRequestState::Failed)
            {
                return std::unexpected(Failure_.Load());
            }
            return {};
        }
    }

    [[nodiscard]] auto QuicConnectionLifecycle::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return DrainOwned(shared_from_this());
    }

    [[nodiscard]] auto QuicConnectionLifecycle::DrainOwned(
        std::shared_ptr<QuicConnectionLifecycle> Owner)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Owner->CanDispatch())
        {
            const auto Failure = Owner->Failure_.Load();
            if (Failure.Failed())
            {
                co_return std::unexpected(Failure);
            }
            if (auto State = Owner->Lifetime_.lock())
            {
                if (const auto CloseFailure = State->PendingCloseFailure())
                {
                    co_return std::unexpected(*CloseFailure);
                }
            }
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return co_await boost::asio::co_spawn(
            Owner->Executor(), Owner->DrainOnExecutor(), boost::asio::use_awaitable);
    }

    [[nodiscard]] auto QuicConnectionLifecycle::DrainOnExecutor()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto CloseRequest = RequestClose();
        if (!CloseRequest)
        {
            const auto PriorFailure = Failure_.Load();
            if (PriorFailure.Failed())
            {
                co_return std::unexpected(PriorFailure);
            }
            co_return std::unexpected(CloseRequest.error());
        }
        const auto Drained = co_await Barrier_.Drain();
        if (!Drained)
        {
            const auto Failure = Failure_.Load();
            if (Failure.Failed())
            {
                co_return std::unexpected(Failure);
            }
            co_return std::unexpected(Drained.error());
        }
        const auto Failure = Failure_.Load();
        if (Failure.Failed())
        {
            co_return std::unexpected(Failure);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    [[nodiscard]] auto QuicConnectionLifecycle::NativeServer() const
        -> std::shared_ptr<Prism::Quic::Server>
    {
        return Server_;
    }

    [[nodiscard]] auto QuicConnectionLifecycle::Options() -> Prism::Quic::ServerOptions
    {
        Prism::Quic::ServerOptions Value;
        Value.Executor = Listener_.Executor;
        Value.Socket = Listener_.Socket;
        Value.TlsContext = Listener_.Tls;
        Value.Sender = Listener_.Sender;
        Value.Generation = Generation_;
        Value.ExternalReceive = true;
        Value.OnClosed = [Weak = weak_from_this()]
        {
            if (auto Owner = Weak.lock())
            {
                Owner->RequestCloseFromNativeNotification();
            }
        };
        return Value;
    }

    auto QuicConnectionLifecycle::Install(Prism::Quic::ServerOptions Value) -> void
    {
        Server_ = std::make_shared<Prism::Quic::Server>(std::move(Value));
    }

    [[nodiscard]] auto QuicConnectionLifecycle::Executor() const
        -> boost::asio::any_io_executor
    {
        return Reclaimer_->Executor();
    }

    [[nodiscard]] auto QuicConnectionLifecycle::SourceIp() const -> std::string
    {
        return Peer_.address().to_string();
    }

    [[nodiscard]] auto QuicConnectionLifecycle::Metadata() const noexcept
        -> const Prism::Contract::RequestMetadata&
    {
        return Metadata_;
    }

    auto QuicConnectionLifecycle::RecordProtocolFailure(
        Prism::Fault::Failure Reason) noexcept -> void
    {
        RecordFailure(Reason);
    }

    [[nodiscard]] auto QuicConnectionLifecycle::CanDispatch() const noexcept -> bool
    {
        return (!Context_ || Context_->CanDispatch()) && Reclaimer_->CanDispatch();
    }

    auto QuicConnectionLifecycle::RequestCloseFromNativeNotification() noexcept -> void
    {
        const auto Result = RequestClose();
        if (Result)
        {
            return;
        }
        if (CloseRequest_.load(std::memory_order_acquire) == CloseRequestState::Failed)
        {
            return;
        }
        if (auto State = Lifetime_.lock())
        {
            State->RetainRejectedCloseRequest(Result.error());
        }
    }

    auto QuicConnectionLifecycle::RecordFailure(Prism::Fault::Failure Reason) noexcept -> void
    {
        if (Reason.Succeeded())
        {
            Reason = {Prism::Fault::Code::Blocked};
        }
        (void)Failure_.TrySet(Reason);
        const auto First = Failure_.Load();
        Barrier_.Block();
        if (auto State = Lifetime_.lock())
        {
            State->Failed(First);
        }
    }

    auto QuicConnectionLifecycle::PublishFatal(std::exception_ptr Error) noexcept -> void
    {
        if (Context_ && Context_->Fatal)
        {
            Context_->Fatal->Publish(std::move(Error));
        }
        RecordFailure({Prism::Fault::Code::Blocked});
    }

    auto QuicConnectionLifecycle::StartFinalizer() -> void
    {
        auto State = CloseRequest_.load(std::memory_order_acquire);
        while (State == CloseRequestState::Submitting ||
            State == CloseRequestState::Queued)
        {
            if (CloseRequest_.compare_exchange_weak(
                    State, CloseRequestState::Finalizing,
                    std::memory_order_acq_rel, std::memory_order_acquire))
            {
                break;
            }
        }
        if (State != CloseRequestState::Submitting && State != CloseRequestState::Queued)
        {
            return;
        }
        try
        {
            CloseProtocol();
        }
        catch (...)
        {
            PublishFatal(std::current_exception());
        }
        try
        {
            if (Server_)
            {
                Server_->Close();
            }
        }
        catch (...)
        {
            PublishFatal(std::current_exception());
        }
        auto Self = shared_from_this();
        try
        {
            auto FinalizationCompletion = [Self](
                std::exception_ptr Error,
                std::expected<void, Prism::Fault::Failure> Result)
            {
                if (Error) Self->PublishFatal(std::move(Error));
                else Self->Complete(std::move(Result));
            };
            boost::asio::co_spawn(Executor(), Self->Finalize(),
                std::move(FinalizationCompletion));
        }
        catch (...)
        {
            PublishFatal(std::current_exception());
            CloseRequest_.store(CloseRequestState::Failed, std::memory_order_release);
        }
    }

    [[nodiscard]] auto QuicConnectionLifecycle::Finalize()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        auto FirstFailure = std::expected<void, Prism::Fault::Failure>{};
        const auto PriorFailure = Failure_.Load();
        if (PriorFailure.Failed())
        {
            FirstFailure = std::unexpected(PriorFailure);
        }
        if (Server_)
        {
            const auto NativeDrain = co_await Server_->Drain();
            if (!NativeDrain && FirstFailure)
            {
                FirstFailure = std::unexpected(NativeDrain.error());
            }
        }
        const auto ProtocolDrain = co_await DrainProtocol();
        if (!ProtocolDrain && FirstFailure)
        {
            FirstFailure = std::unexpected(ProtocolDrain.error());
        }
        if (!FirstFailure)
        {
            co_return std::unexpected(FirstFailure.error());
        }
        const auto Identity = Metadata_.TaskIdentity;
        if (Traffic_ && Identity.SessionId.Value() != 0U)
        {
            const auto Retired = co_await Prism::Foundation::RetireTraffic(Traffic_,
                Prism::Foundation::TrafficRetirement{
                    Prism::Foundation::SessionTrafficOwner{
                        Identity.WorkerId, Identity.SessionId}});
            (void)Retired;
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto QuicConnectionLifecycle::Complete(
        std::expected<void, Prism::Fault::Failure> Result) noexcept -> void
    {
        if (!Result)
        {
            RecordFailure(Result.error());
            CloseRequest_.store(CloseRequestState::Failed, std::memory_order_release);
            return;
        }
        Server_.reset();
        Listener_ = {};
        try
        {
            if (Observer_)
            {
                Observer_();
            }
        }
        catch (...)
        {
        }
        Observer_ = {};
        CloseRequest_.store(CloseRequestState::Completed, std::memory_order_release);
        if (auto State = Lifetime_.lock())
        {
            State->Finished(this);
        }
        Barrier_.Seal();
        GenerationUse_ = {};
        Barrier_.Leave();
    }

} // namespace Prism::Protocols
