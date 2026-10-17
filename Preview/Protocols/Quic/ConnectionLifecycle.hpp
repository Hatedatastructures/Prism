/** @file QuicConnectionLifecycle.hpp @brief 单连接实际 native/finalizer 的统一关闭门与实物保活。 */
#pragma once
#include <Preview/Protocols/Common/QuicBindingState.hpp>
#include <Preview/Protocols/Quic/Native.hpp>
#include <Preview/Contract/Services/Quic.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <boost/asio/co_spawn.hpp>
#include <atomic>
#include <expected>
#include <utility>
namespace Preview::Protocols
{
    struct QuicConnectionPreparation final
    {
        Preview::Contract::QuicListenerResources Listener;
        Preview::Contract::QuicAcceptRequest Request;
        std::shared_ptr<QuicBindingState> Lifetime;
        Preview::Foundation::GenerationPin Generation;
        std::shared_ptr<Preview::Foundation::TrafficSink> Traffic{};
    };
    /** @brief 实际 owner pin 独立 Io/PMR，所有排队关闭通知只 weak 联系 owner。
     * @details finalizer await 协议 child 和 native I/O，完成后退一次计数；外部租约保留
     *          原 generation 和 DrainBarrier 所需的独立 Io/PMR，最后租约先析构屏障再释放 context。
     */
    class QuicConnectionLifecycle : public Preview::Contract::QuicConnectionOwner,
        public std::enable_shared_from_this<QuicConnectionLifecycle>
    {
        enum class CloseRequestState : std::uint8_t
        {
            Open,
            Submitting,
            Queued,
            Finalizing,
            Completed,
            Failed,
        };

    public:
        explicit QuicConnectionLifecycle(QuicConnectionPreparation Input)
            :Listener_(std::move(Input.Listener)),NativeTls_(Listener_.Tls),
             Peer_(Input.Request.Peer),Observer_(std::move(Input.Request.OnClosed)),
             Metadata_(std::move(Input.Request.Metadata)),Traffic_(std::move(Input.Traffic)),
              Lifetime_(Input.Lifetime),Generation_(std::move(Input.Generation)),
              GenerationUse_(std::move(Input.Request.GenerationUse)),
             Context_(Preview::Executor::ContextOwner::Find(Listener_.Executor)),
             Reclaimer_(std::make_shared<Preview::Executor::ExecutorReclaimer>(Listener_.Executor)),Barrier_(Reclaimer_)
        {(void)Barrier_.Enter();}
        auto Start() -> void override
        {
            if (Server_) Server_->Start();
        }
        [[nodiscard]] auto ReceivePacket(
            const std::span<const std::byte> Payload,
            const boost::asio::ip::udp::endpoint& Peer) -> bool override
        {
            return Server_ && Server_->ReceivePacket(Payload, Peer);
        }
        [[nodiscard]] auto State() const noexcept -> Preview::Contract::QuicConnectionState override
        {
            if (!Server_) return {false, true};
            const auto Health = Server_->Health();
            return {Health.HandshakeReady, Health.Closed};
        }
        [[nodiscard]] auto RequestClose() noexcept
            -> std::expected<void, Preview::Fault::Failure> override
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
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                }

                const auto Self = weak_from_this().lock();
                if (!Self)
                {
                    return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
                }
                if (!CanDispatch())
                {
                    return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                }
                if (!CloseRequest_.compare_exchange_weak(
                        State, CloseRequestState::Submitting,
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    continue;
                }

                const auto Posted = Reclaimer_->Post(
                    [Self] { Self->StartFinalizer(); });
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
        [[nodiscard]] auto Drain()
            ->boost::asio::awaitable<std::expected<void,Preview::Fault::Failure>> override
        {
            return DrainOwned(shared_from_this());
        }
    private:
        /** @brief 在创建等待任务前固定 owner，并将实际关闭与排空置于 owner executor。 */
        [[nodiscard]] static auto DrainOwned(std::shared_ptr<QuicConnectionLifecycle> Owner)
            ->boost::asio::awaitable<std::expected<void,Preview::Fault::Failure>>
        {
            if(!Owner->CanDispatch())
            {
                const auto Failure=Owner->Failure_.Load();
                if(Failure.Failed())co_return std::unexpected(Failure);
                if(auto State=Owner->Lifetime_.lock())
                    if(const auto CloseFailure=State->PendingCloseFailure())
                        co_return std::unexpected(*CloseFailure);
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            co_return co_await boost::asio::co_spawn(Owner->Executor(),
                Owner->DrainOnExecutor(), boost::asio::use_awaitable);
        }
        [[nodiscard]] auto DrainOnExecutor()
            ->boost::asio::awaitable<std::expected<void,Preview::Fault::Failure>>
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
            const auto Drained=co_await Barrier_.Drain();
            if(!Drained)
            {
                const auto Failure=Failure_.Load();
                if(Failure.Failed())co_return std::unexpected(Failure);
                co_return std::unexpected(Drained.error());
            }
            const auto Failure=Failure_.Load();
            if(Failure.Failed())co_return std::unexpected(Failure);
            co_return std::expected<void,Preview::Fault::Failure>{};
        }
    protected:
        /** @brief 协议内部共享同一 native server；不向 Boundary 公开具体实现或关闭权。 */
        [[nodiscard]] auto NativeServer() const -> std::shared_ptr<Preview::Quic::Server>
        {
            return Server_;
        }
        [[nodiscard]] auto Options()->Preview::Quic::ServerOptions
        {
            Preview::Quic::ServerOptions Value;Value.Executor=Listener_.Executor;Value.Socket=Listener_.Socket;
            Value.TlsContext=Listener_.Tls;Value.Sender=Listener_.Sender;
            Value.Generation=Generation_;Value.ExternalReceive=true;
            Value.OnClosed=[Weak=weak_from_this()]
            {
                if (auto Owner=Weak.lock()) Owner->RequestCloseFromNativeNotification();
            };
            return Value;
        }
        auto Install(Preview::Quic::ServerOptions Value)->void {Server_=std::make_shared<Preview::Quic::Server>(std::move(Value));}
        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor {return Reclaimer_->Executor();}
        [[nodiscard]] auto SourceIp() const -> std::string {return Peer_.address().to_string();}
        [[nodiscard]] auto Metadata() const noexcept -> const Preview::Contract::RequestMetadata &
        { return Metadata_; }
        virtual auto CloseProtocol() -> void = 0;
        [[nodiscard]] virtual auto DrainProtocol()
            -> boost::asio::awaitable<std::expected<void,Preview::Fault::Failure>> = 0;
    private:
        [[nodiscard]] auto CanDispatch() const noexcept -> bool {return (!Context_ || Context_->CanDispatch()) && Reclaimer_->CanDispatch();}
        auto RequestCloseFromNativeNotification() noexcept -> void
        {
            const auto Result=RequestClose();
            if(Result)return;
            if(CloseRequest_.load(std::memory_order_acquire)==CloseRequestState::Failed)return;
            if(auto State=Lifetime_.lock())State->RetainRejectedCloseRequest(Result.error());
        }
        auto RecordFailure(Preview::Fault::Failure Reason) noexcept -> void
        {
            if(Reason.Succeeded())Reason={Preview::Fault::Code::Blocked};
            Failure_.TrySet(Reason);
            const auto First=Failure_.Load();
            Barrier_.Block();
            if(auto State=Lifetime_.lock())State->Failed(First);
        }
        auto PublishFatal(std::exception_ptr Error) noexcept -> void
        {
            if(Context_ && Context_->Fatal)Context_->Fatal->Publish(std::move(Error));
            RecordFailure({Preview::Fault::Code::Blocked});
        }
        auto StartFinalizer()->void
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
            if (State != CloseRequestState::Submitting &&
                State != CloseRequestState::Queued)
            {
                return;
            }
            try{CloseProtocol();}
            catch(...){PublishFatal(std::current_exception());}
            try{if(Server_)Server_->Close();}
            catch(...){PublishFatal(std::current_exception());}
            auto Self=shared_from_this();
            try
            {
                boost::asio::co_spawn(Executor(),Self->Finalize(),
                    [Self](std::exception_ptr Error,std::expected<void,Preview::Fault::Failure> Result)
                    {if(Error)Self->PublishFatal(std::move(Error));else Self->Complete(std::move(Result));});
            }
            catch(...)
            {
                PublishFatal(std::current_exception());
                CloseRequest_.store(CloseRequestState::Failed, std::memory_order_release);
            }
        }
        [[nodiscard]] auto Finalize()
            ->boost::asio::awaitable<std::expected<void,Preview::Fault::Failure>>
        {
            auto FirstFailure=std::expected<void,Preview::Fault::Failure>{};
            const auto PriorFailure=Failure_.Load();
            if(PriorFailure.Failed())FirstFailure=std::unexpected(PriorFailure);
            if(Server_)
            {
                const auto NativeDrain=co_await Server_->Drain();
                if(!NativeDrain && FirstFailure)FirstFailure=std::unexpected(NativeDrain.error());
            }
            const auto ProtocolDrain=co_await DrainProtocol();
            if(!ProtocolDrain && FirstFailure)FirstFailure=std::unexpected(ProtocolDrain.error());
            if(!FirstFailure)co_return std::unexpected(FirstFailure.error());
            const auto Identity=Metadata_.TaskIdentity;
            if(Traffic_ && Identity.SessionId.Value()!=0U)
            {
                const auto Retired=co_await Preview::Foundation::RetireTraffic(Traffic_,
                    Preview::Foundation::TrafficRetirement{Preview::Foundation::SessionTrafficOwner{
                        Identity.WorkerId,Identity.SessionId}});
                (void)Retired;
            }
            co_return std::expected<void,Preview::Fault::Failure>{};
        }
        auto Complete(std::expected<void,Preview::Fault::Failure> Result) noexcept -> void
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
        Preview::Contract::QuicListenerResources Listener_;
        /** @brief 在原生监听资源释放后仍由 opaque Native owner 保留 TLS 原料。 */
        std::shared_ptr<boost::asio::ssl::context> NativeTls_;
        boost::asio::ip::udp::endpoint Peer_;
        std::function<void()> Observer_;
        Preview::Contract::RequestMetadata Metadata_;
        std::shared_ptr<Preview::Foundation::TrafficSink> Traffic_;
        std::weak_ptr<QuicBindingState> Lifetime_;
        Preview::Foundation::GenerationPin Generation_;
        Preview::Contract::QuicConnectionGenerationLease GenerationUse_;
        std::shared_ptr<Preview::Executor::ContextOwner> Context_;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer_;
        Preview::Lifecycle::DrainBarrier Barrier_;
        std::shared_ptr<Preview::Quic::Server> Server_;
        std::atomic<CloseRequestState> CloseRequest_{CloseRequestState::Open};
        Preview::Fault::FailureState Failure_;
    };
}
