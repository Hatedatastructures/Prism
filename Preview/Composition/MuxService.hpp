/**
 * @file MuxService.hpp
 * @brief Preview-owned smux/yamux server service contract.
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Lifecycle/TaskState.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <Preview/Protocols/Mux/Stream.hpp>
#include <Preview/Protocols/Mux/Yamux/Yamux.hpp>
#include <Preview/Runtime/SessionControl.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Middleware
{

    class Context;

} // namespace Preview::Middleware

namespace Preview::Composition
{

    namespace Net = boost::asio;

    enum class MuxMode : std::uint8_t
    {
        Auto,
        Smux,
        Yamux,
    };

    struct MuxServiceOptions final
    {
        using StreamHandler = std::function<Net::awaitable<Preview::Fault::Code>(
            Preview::SharedTransmission, const Preview::Lifecycle::TaskIdentity &)>;
        using RootWaitingHandler = std::function<void()>;

        MuxMode Mode{MuxMode::Auto};
        std::shared_ptr<Preview::Runtime::SessionControl> Control{};
        Preview::Lifecycle::TaskIdentity Identity{};
        std::size_t MaxStreams{256};
        std::chrono::milliseconds Timeout{0};
        StreamHandler StreamHandlerFn{};
        RootWaitingHandler RootWaitingFn{};
    };

    class MuxService final
    {
    public:
        explicit MuxService(MuxServiceOptions OptionsValue)
            : Options_(std::move(OptionsValue))
        {
        }

        auto SetStreamHandler(MuxServiceOptions::StreamHandler Handler) -> void
        {
            Options_.StreamHandlerFn = std::move(Handler);
        }

        [[nodiscard]] auto Run(
            Preview::SharedTransmission Inbound,
            Preview::Middleware::Context &Context) -> Net::awaitable<Preview::Fault::Code>
        {
            if (!Inbound)
            {
                co_return Preview::Fault::Code::IoError;
            }
            if (!Options_.StreamHandlerFn)
            {
                co_return Preview::Fault::Code::NotSupported;
            }
            auto Control = Context.Control ? Context.Control : Options_.Control;
            if (Control)
            {
                (void)Control->Bind(Inbound->Executor());
            }
            else
            {
                Control = std::make_shared<Preview::Runtime::SessionControl>(Inbound->Executor());
            }
            switch (Options_.Mode)
            {
            case MuxMode::Yamux:
                co_return co_await RunServer<Preview::Mux::Yamux::Server<>>(
                    std::move(Inbound), std::move(Control), Context.TaskIdentity);
            case MuxMode::Auto:
            case MuxMode::Smux:
                co_return co_await RunServer<Preview::Mux::Smux::Server<>>(
                    std::move(Inbound), std::move(Control), Context.TaskIdentity);
            }
            co_return Preview::Fault::Code::NotSupported;
        }

        auto Stop() noexcept -> void
        {
            while (true)
            {
                auto Current = Registry_.load(std::memory_order_acquire);
                if (Current->Stopping)
                {
                    return;
                }
                auto Updated = std::make_shared<RegistryState>(*Current);
                Updated->Stopping = true;
                std::shared_ptr<const RegistryState> Desired = std::move(Updated);
                if (Registry_.compare_exchange_weak(
                        Current, Desired, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    StopRoots(Desired->Roots);
                    return;
                }
            }
        }

        [[nodiscard]] auto IsStopping() const noexcept -> bool
        {
            return Registry_.load(std::memory_order_acquire)->Stopping;
        }

    private:
        /// TaskRegistry 持有 awaitable；请求中的值必须由协程帧拥有。
        struct StreamOperationRequest final
        {
            MuxServiceOptions::StreamHandler Handler;
            Preview::SharedTransmission Stream;
            Preview::Lifecycle::TaskIdentity Identity;
        };

        struct RootStopState final
        {
            enum class Phase : std::uint8_t
            {
                Active,
                Stopping,
                Finished,
                Stopped,
            };

            explicit RootStopState(std::function<void()> StopFunctionValue)
                : StopFunction_(std::move(StopFunctionValue))
            {
            }

            auto Stop() noexcept -> void
            {
                auto Expected = Phase::Active;
                if (!Phase_.compare_exchange_strong(
                        Expected, Phase::Stopping, std::memory_order_acq_rel))
                {
                    return;
                }
                try
                {
                    StopFunction_();
                }
                catch (...)
                {
                }
            }

            [[nodiscard]] auto IsStopping() const noexcept -> bool
            {
                return Phase_.load(std::memory_order_acquire) == Phase::Stopping;
            }

            auto Finish() noexcept -> void
            {
                auto Expected = Phase::Active;
                if (Phase_.compare_exchange_strong(
                        Expected, Phase::Finished, std::memory_order_acq_rel))
                {
                    return;
                }
                if (Expected == Phase::Stopping)
                {
                    (void)Phase_.compare_exchange_strong(
                        Expected, Phase::Stopped, std::memory_order_acq_rel);
                }
            }

            [[nodiscard]] auto WasStopped() const noexcept -> bool
            {
                const auto PhaseValue = Phase_.load(std::memory_order_acquire);
                return PhaseValue == Phase::Stopping || PhaseValue == Phase::Stopped;
            }

        private:
            std::function<void()> StopFunction_;
            std::atomic<Phase> Phase_{Phase::Active};
        };

        using RootList = std::vector<std::weak_ptr<RootStopState>>;

        struct RegistryState final
        {
            bool Stopping{false};
            RootList Roots;
        };

        // COW 发布让停止标志与 root 集合共享一个线性化点。
        auto RegisterRoot(const std::shared_ptr<RootStopState> &Root) -> void
        {
            while (true)
            {
                auto Current = Registry_.load(std::memory_order_acquire);
                if (Current->Stopping)
                {
                    Root->Stop();
                    return;
                }
                auto Updated = std::make_shared<RootList>();
                Updated->reserve(Current->Roots.size() + 1);
                for (const auto &Existing : Current->Roots)
                {
                    if (const auto ExistingRoot = Existing.lock())
                    {
                        Updated->push_back(ExistingRoot);
                    }
                }
                Updated->push_back(Root);
                auto Next = std::make_shared<RegistryState>();
                Next->Roots = std::move(*Updated);
                std::shared_ptr<const RegistryState> Desired = std::move(Next);
                if (Registry_.compare_exchange_weak(
                        Current, Desired, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        auto UnregisterRoot(const std::shared_ptr<RootStopState> &Root) -> void
        {
            while (true)
            {
                auto Current = Registry_.load(std::memory_order_acquire);
                auto Updated = std::make_shared<RootList>();
                Updated->reserve(Current->Roots.size());
                for (const auto &Existing : Current->Roots)
                {
                    if (const auto ExistingRoot = Existing.lock(); ExistingRoot && ExistingRoot != Root)
                    {
                        Updated->push_back(ExistingRoot);
                    }
                }
                auto Next = std::make_shared<RegistryState>(*Current);
                Next->Roots = std::move(*Updated);
                std::shared_ptr<const RegistryState> Desired = std::move(Next);
                if (Registry_.compare_exchange_weak(
                        Current, Desired, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        static auto StopRoots(const RootList &Roots) noexcept -> void
        {
            for (const auto &WeakRoot : Roots)
            {
                if (const auto Root = WeakRoot.lock())
                {
                    Root->Stop();
                }
            }
        }

        auto NotifyRootWaiting() const noexcept -> void
        {
            if (!Options_.RootWaitingFn)
            {
                return;
            }
            try
            {
                Options_.RootWaitingFn();
            }
            catch (...)
            {
            }
        }

        [[nodiscard]] static auto FinishRoot(
            std::shared_ptr<RootStopState> RootStop,
            std::shared_ptr<Preview::Runtime::SessionControl> Control) -> Net::awaitable<void>
        {
            if (RootStop->IsStopping() && Control)
            {
                Control->Cancel();
            }
            if (Control)
            {
                co_await Control->Drain();
            }
            RootStop->Finish();
        }

        [[nodiscard]] static auto RunStreamOperation(StreamOperationRequest Request)
            -> Net::awaitable<void>
        {
            const auto Code = co_await Request.Handler(std::move(Request.Stream), Request.Identity);
            if (Preview::Fault::Failed(Code))
            {
                co_return;
            }
        }

        template <typename Server>
        [[nodiscard]] auto RunServer(
            Preview::SharedTransmission Inbound,
            std::shared_ptr<Preview::Runtime::SessionControl> Control,
            const Preview::Lifecycle::TaskIdentity ParentIdentity)
            -> Net::awaitable<Preview::Fault::Code>
        {
            auto ServerValue = std::make_shared<Server>();
            Preview::Mux::SessionOptions SessionOptions;
            SessionOptions.Control = Control;
            SessionOptions.Identity = ParentIdentity;
            SessionOptions.Role = Preview::Role::Server;
            SessionOptions.MaxStreams = Options_.MaxStreams;
            SessionOptions.timeout = Options_.Timeout;
            if (!ServerValue->Accept(std::move(Inbound), SessionOptions))
            {
                co_return Preview::Fault::Code::IoError;
            }
            const auto SessionValue = ServerValue->Session();
            if (!SessionValue)
            {
                co_return Preview::Fault::Code::IoError;
            }

            auto RootStop = std::make_shared<RootStopState>([SessionValue]
            {
                SessionValue->Cancel();
            });
            RegisterRoot(RootStop);

            if (Control)
            {
                const std::weak_ptr<RootStopState> RootOwner = RootStop;
                (void)Control->AddCancelHook([RootOwner]
                {
                    if (const auto Root = RootOwner.lock())
                    {
                        Root->Stop();
                    }
                });
            }

            while (!RootStop->IsStopping())
            {
                NotifyRootWaiting();
                auto Stream = co_await ServerValue->AcceptStream();
                if (!Stream)
                {
                    break;
                }
                auto Identity = Options_.Identity;
                if (const auto Typed = std::static_pointer_cast<Preview::Mux::StreamTransmission>(Stream);
                    Typed && Typed->Handle())
                {
                    Identity.StreamId = Preview::StreamId{Typed->Handle()->Id()};
                }
                auto Handler = Options_.StreamHandlerFn;
                const auto CancelStream = Stream;
                if (!Control->Start(
                        Preview::Lifecycle::TaskRequest{
                            .Identity = Identity,
                            .Cancel = [CancelStream]
                            {
                                if (CancelStream)
                                {
                                    CancelStream->Cancel();
                                    CancelStream->Close();
                                }
                            }},
                        RunStreamOperation(StreamOperationRequest{
                            std::move(Handler), std::move(Stream), Identity})))
                {
                    if (SessionValue)
                    {
                        co_await SessionValue->Close();
                    }
                    co_await FinishRoot(RootStop, Control);
                    UnregisterRoot(RootStop);
                    co_return Preview::Fault::Code::Canceled;
                }
            }
            if (SessionValue)
            {
                co_await SessionValue->Close();
            }
            co_await FinishRoot(RootStop, Control);
            UnregisterRoot(RootStop);
            co_return RootStop->WasStopped() ? Preview::Fault::Code::Canceled
                                             : Preview::Fault::Code::Success;
        }

        MuxServiceOptions Options_;
        std::atomic<std::shared_ptr<const RegistryState>> Registry_{
            std::make_shared<const RegistryState>()};
    };

} // namespace Preview::Composition
