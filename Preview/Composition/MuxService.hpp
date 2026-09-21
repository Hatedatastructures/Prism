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
#include <string>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Lifecycle/TaskState.hpp>
#include <Preview/Composition/H2MuxServer.hpp>
#include <Preview/Composition/SingMux.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <Preview/Protocols/Mux/Stream.hpp>
#include <Preview/Protocols/Mux/H2Mux/H2Mux.hpp>
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
        H2Mux,
    };

    [[nodiscard]] inline auto MuxModeName(const MuxMode Mode) noexcept -> std::string_view
    {
        switch (Mode)
        {
        case MuxMode::Auto: return "auto";
        case MuxMode::Smux: return "smux";
        case MuxMode::Yamux: return "yamux";
        case MuxMode::H2Mux: return "h2mux";
        }
        return "auto";
    }

    [[nodiscard]] inline auto ParseMuxMode(const std::string_view Name) noexcept
        -> std::optional<MuxMode>
    {
        if (Name == "auto" || Name == "Auto") return MuxMode::Auto;
        if (Name == "smux" || Name == "Smux") return MuxMode::Smux;
        if (Name == "yamux" || Name == "Yamux") return MuxMode::Yamux;
        if (Name == "h2mux" || Name == "H2Mux") return MuxMode::H2Mux;
        return std::nullopt;
    }

    struct MuxServiceOptions final
    {
        using StreamHandler = std::function<Net::awaitable<Preview::Fault::Code>(
            Preview::SharedTransmission, const Preview::Lifecycle::TaskIdentity &)>;
        using StreamResultHandler = std::function<void(
            std::uint16_t, MuxMode, const Preview::Lifecycle::TaskIdentity &, Preview::Fault::Code)>;
        using RootWaitingHandler = std::function<void()>;

        MuxMode Mode{MuxMode::Auto};
        std::shared_ptr<Preview::Runtime::SessionControl> Control{};
        Preview::Lifecycle::TaskIdentity Identity{};
        std::size_t MaxStreams{256};
        std::chrono::milliseconds Timeout{0};
        bool RequireSingMuxProtocol{false};
        StreamHandler StreamHandlerFn{};
        StreamResultHandler StreamResultFn{};
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

        auto SetStreamResultHandler(MuxServiceOptions::StreamResultHandler Handler) -> void
        {
            Options_.StreamResultFn = std::move(Handler);
        }

        [[nodiscard]] auto Run(
            Preview::SharedTransmission Inbound,
            Preview::Middleware::Context &Context,
            MuxServiceOptions::StreamHandler Handler = {}) -> Net::awaitable<Preview::Fault::Code>
        {
            if (!Inbound)
            {
                co_return Preview::Fault::Code::IoError;
            }
            if (!Handler)
            {
                Handler = Options_.StreamHandlerFn;
            }
            if (!Handler)
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
            auto EffectiveMode = Options_.Mode;
            const auto *ContextMux = Context.DataPlane.Mux();
            const bool ExplicitContextMode =
                ContextMux != nullptr && !ContextMux->Mode.empty() &&
                ContextMux->Mode != "auto";
            const bool RequireSessionRequest = Options_.RequireSingMuxProtocol;
            const bool RequireStreamRequest =
                Options_.RequireSingMuxProtocol || ExplicitContextMode;
            if (ContextMux && !ContextMux->Mode.empty())
            {
                const auto ContextMode = ParseMuxMode(ContextMux->Mode);
                if (!ContextMode)
                {
                    co_return Preview::Fault::Code::NotSupported;
                }
                if (*ContextMode != MuxMode::Auto)
                {
                    if (Options_.Mode != MuxMode::Auto && Options_.Mode != *ContextMode)
                    {
                        co_return Preview::Fault::Code::NotSupported;
                    }
                    EffectiveMode = *ContextMode;
                }
            }
            if (RequireSessionRequest)
            {
                const auto Request = co_await SingMux::ReadSessionRequest(Inbound);
                if (!Request)
                {
                    co_return Preview::Fault::Code::ProtocolError;
                }
                switch (Request->ProtocolValue)
                {
                case SingMux::Protocol::Smux:
                    EffectiveMode = MuxMode::Smux;
                    break;
                case SingMux::Protocol::Yamux:
                    EffectiveMode = MuxMode::Yamux;
                    break;
                case SingMux::Protocol::H2Mux:
                    EffectiveMode = MuxMode::H2Mux;
                    break;
                }
                const auto RequestedMode = EffectiveMode;
                if (const auto *MuxRoot = Context.DataPlane.Mux(); MuxRoot &&
                    !MuxRoot->Mode.empty())
                {
                    const auto ContextMode = ParseMuxMode(MuxRoot->Mode);
                    if (ContextMode && *ContextMode != MuxMode::Auto &&
                        *ContextMode != RequestedMode)
                    {
                        co_return Preview::Fault::Code::NotSupported;
                    }
                }
                if (Options_.Mode != MuxMode::Auto && Options_.Mode != RequestedMode)
                {
                    co_return Preview::Fault::Code::NotSupported;
                }
            }
            auto MuxIdentity = Context.TaskIdentity;
            MuxIdentity.TaskId = Preview::TaskId{};
            if (EffectiveMode == MuxMode::H2Mux &&
                (RequireSessionRequest || ExplicitContextMode))
            {
                co_return co_await RunH2Server(
                    std::move(Inbound), std::move(Control), MuxIdentity,
                    RequireStreamRequest, Context.detected, EffectiveMode,
                    Handler, Options_.StreamResultFn);
            }
            switch (EffectiveMode)
            {
            case MuxMode::Yamux:
                co_return co_await RunServer<Preview::Mux::Yamux::Server<>>(
                    std::move(Inbound), std::move(Control), MuxIdentity,
                    RequireStreamRequest, Context.detected, EffectiveMode,
                    Handler, Options_.StreamResultFn);
            case MuxMode::H2Mux:
                co_return co_await RunServer<Preview::Mux::H2Mux::Server<>>(
                    std::move(Inbound), std::move(Control), MuxIdentity,
                    RequireStreamRequest, Context.detected, EffectiveMode,
                    Handler, Options_.StreamResultFn);
            case MuxMode::Auto:
            case MuxMode::Smux:
                co_return co_await RunServer<Preview::Mux::Smux::Server<>>(
                    std::move(Inbound), std::move(Control), MuxIdentity,
                    RequireStreamRequest, Context.detected, EffectiveMode,
                    Handler, Options_.StreamResultFn);
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
            /// 为 true 时先在该流自己的任务里解析 sing-mux StreamRequest，
            /// 避免接受循环被某条静默流的首帧阻塞（队头阻塞）。
            bool RequireSingMuxProtocol{false};
            std::uint16_t Protocol{0};
            MuxMode Mode{MuxMode::Auto};
            MuxServiceOptions::StreamResultHandler ResultHandler{};
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
            if (Request.RequireSingMuxProtocol)
            {
                const auto Parsed = co_await SingMux::ReadStreamRequest(Request.Stream);
                if (!Parsed || Parsed->Udp)
                {
                    Request.Stream->Close();
                    co_return;
                }
                Request.Stream = std::make_shared<SingMux::ServerStream>(
                    std::move(Request.Stream), std::move(Parsed->Target));
            }
            const auto Code = co_await Request.Handler(std::move(Request.Stream), Request.Identity);
            if (Request.ResultHandler)
            {
                Request.ResultHandler(Request.Protocol, Request.Mode, Request.Identity, Code);
            }
            if (Preview::Fault::Failed(Code))
            {
                co_return;
            }
        }

        [[nodiscard]] auto RunH2Server(
            Preview::SharedTransmission Inbound,
            std::shared_ptr<Preview::Runtime::SessionControl> Control,
            const Preview::Lifecycle::TaskIdentity ParentIdentity,
            const bool RequireStreamRequest,
            const std::uint16_t Protocol,
            const MuxMode Mode,
            const MuxServiceOptions::StreamHandler &Handler,
            const MuxServiceOptions::StreamResultHandler &ResultHandler)
            -> Net::awaitable<Preview::Fault::Code>
        {
            auto ServerValue = std::make_shared<SingMux::H2Server>(std::move(Inbound));
            auto LoopControl = std::make_shared<Preview::Runtime::SessionControl>(
                ServerValue->Executor());
            Preview::Lifecycle::TaskRequest LoopRequest;
            LoopRequest.Identity = ParentIdentity;
            LoopRequest.Identity.TaskId = Preview::TaskId{};
            LoopRequest.Cancel = [ServerValue]
            {
                ServerValue->Cancel();
            };
            if (!LoopControl->Start(std::move(LoopRequest), ServerValue->RunLoop()))
            {
                ServerValue->Close();
                co_return Preview::Fault::Code::Canceled;
            }

            auto RootStop = std::make_shared<RootStopState>([ServerValue]
            {
                ServerValue->Cancel();
            });
            RegisterRoot(RootStop);
            const std::weak_ptr<RootStopState> RootOwner = RootStop;
            (void)Control->AddCancelHook([RootOwner]
            {
                if (const auto Root = RootOwner.lock())
                {
                    Root->Stop();
                }
            });

            while (!RootStop->IsStopping())
            {
                NotifyRootWaiting();
                auto Stream = co_await ServerValue->AcceptStream();
                if (!Stream)
                {
                    break;
                }
                auto Identity = Options_.Identity;
                Identity.TaskId = Preview::TaskId{};
                if (const auto StreamId = ServerValue->StreamId(Stream); StreamId > 0)
                {
                    Identity.StreamId = Preview::StreamId{
                        static_cast<std::uint64_t>(StreamId)};
                }
                auto StreamHandler = Handler;
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
                            std::move(StreamHandler), std::move(Stream), Identity,
                            RequireStreamRequest, Protocol, Mode, ResultHandler})))
                {
                    ServerValue->Close();
                    co_await FinishRoot(RootStop, Control);
                    UnregisterRoot(RootStop);
                    co_return Preview::Fault::Code::Canceled;
                }
            }
            ServerValue->Close();
            LoopControl->Cancel();
            co_await LoopControl->Drain();
            if (RootStop->WasStopped())
            {
                Control->Cancel();
            }
            UnregisterRoot(RootStop);
            co_return RootStop->WasStopped() ? Preview::Fault::Code::Canceled
                                             : Preview::Fault::Code::Success;
        }

        template <typename Server>
        [[nodiscard]] auto RunServer(
            Preview::SharedTransmission Inbound,
            std::shared_ptr<Preview::Runtime::SessionControl> Control,
            const Preview::Lifecycle::TaskIdentity ParentIdentity,
            const bool RequireStreamRequest,
            const std::uint16_t Protocol,
            const MuxMode Mode,
            const MuxServiceOptions::StreamHandler &Handler,
            const MuxServiceOptions::StreamResultHandler &ResultHandler)
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
            auto SessionValue = ServerValue->Session();
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
                auto StreamHandler = Handler;
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
                            std::move(StreamHandler), std::move(Stream), Identity,
                            RequireStreamRequest, Protocol, Mode, ResultHandler})))
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
