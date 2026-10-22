/** @file RootSession.hpp @brief generic sing-mux 的正式 MuxSession 与 root lease drain。 */
#pragma once
#include <Prism/Protocols/Mux/Detail/Root/RootChild.hpp>
#include <Prism/Protocols/Mux/Detail/Root/RootRetirement.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/system_error.hpp>
#include <atomic>
#include <exception>
#include <system_error>
#include <type_traits>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Protocols/Mux/Yamux/Yamux.hpp>
#include <Prism/Protocols/Mux/H2Mux/Http2Server.hpp>
#include <cstdint>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Mux::Testing
{
    class RootSessionStateFixture;
}

namespace Prism::Mux::Detail
{
    [[nodiscard]] auto IsExpectedRootRunCancellation(
        const std::shared_ptr<RootState> &State,
        const std::expected<void, Prism::Fault::Failure> &Result) noexcept -> bool;
    auto RecordHttp2RunFailure(
        const std::shared_ptr<RootState> &State,
        Prism::Fault::Failure Failure) noexcept -> void;

    class RootSession final : public Prism::Contract::MuxSession
    {
        friend class RootRegistry;
        friend class Testing::RootSessionStateFixture;
        class RootActivity final : public Prism::Contract::CarrierActivity
        {
        public:
            explicit RootActivity(std::shared_ptr<RootState> Value);

            /** @brief 一次封止根准入及现有 child/frame scope，不关闭 inbound。 */
            auto Seal() noexcept -> void override;

            [[nodiscard]] auto Executor() const -> Net::any_io_executor override;

            [[nodiscard]] auto IsRetired() const noexcept -> bool override;

            /** @brief 等待唯一 Run owner 完成 child、frame 和 writer 的真实退栈。 */
            [[nodiscard]] auto Drain()
                -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override;

        private:
            std::shared_ptr<RootState> State_;
        };

        /** @brief 强持有具体 Server；只请求关闭，实际完成由根作用域排空回执提供。 */
        template<class Server>
        class EngineCloseOwner final : public RootEngineControl
        {
        public:
            EngineCloseOwner(std::shared_ptr<Server> Value, std::weak_ptr<RootState> Root)
                : Server_(std::move(Value)), Root_(std::move(Root)) {}
            auto RequestClose() noexcept
                -> std::expected<void, Prism::Fault::Failure> override
            {
                try
                {
                    Server_->Close();
                    return std::expected<void, Prism::Fault::Failure>{};
                }
                catch (...)
                {
                    return std::unexpected(
                        RootState::FailureFromException(std::current_exception()));
                }
            }
            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            {
                if constexpr (std::is_same_v<Server, H2Mux::Http2Server>)
                {
                    return Server_ && Server_->IsRetired();
                }
                return Retired_.load(std::memory_order_acquire);
            }
            [[nodiscard]] auto Drain()
                -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
            {
                if constexpr (std::is_same_v<Server, H2Mux::Http2Server>)
                {
                    const auto Drained = co_await Server_->Drain();
                    const auto Retired = Server_->IsRetired();
                    Retired_.store(Retired, std::memory_order_release);
                    if (!Drained) co_return std::unexpected(Drained.error());
                    if (!Retired)
                    {
                        co_return std::unexpected(
                            Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                    }
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                else if constexpr (requires(Server &Value) { Value.Session(); })
                {
                    const auto Root = Root_.lock();
                    if (!Root)
                    {
                        co_return std::unexpected(
                            Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                    }
                    const auto Receipt = co_await DrainMuxServerTasks(Root, Server_);
                    Retired_.store(Receipt.Retired, std::memory_order_release);
                    if (Receipt.Failure.Failed())
                        co_return std::unexpected(Receipt.Failure);
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                else
                {
                    static_assert(std::is_same_v<Server, H2Mux::Http2Server>,
                        "mux engine owner requires an explicit physical retirement contract");
                }
            }
        private:
            std::shared_ptr<Server> Server_;
            std::weak_ptr<RootState> Root_;
            std::atomic_bool Retired_{false};
        };

    public:
        /** @brief 只从已预预约的唯一 create request 构造正式 root session。 */
        [[nodiscard]] static auto Create(
            Prism::Contract::MuxRootCreateRequest &Request,
            const RootOptions &Options)
            -> std::expected<std::shared_ptr<RootSession>, Prism::Fault::Failure>;
        ~RootSession() override;
        auto SetRetirementOwner(const std::shared_ptr<RootRetirementOwner> &Owner) noexcept -> void;
        [[nodiscard]] auto HistoricalFailure() const noexcept -> Prism::Fault::Failure;
        /** @brief 是否已有正式 Run owner 启动；用于区分已运行 root 与仅注册未运行的 root。 */
        [[nodiscard]] auto WasStarted() const noexcept -> bool;
        /** @brief 是否已由 root owner 正常请求停止，避免 registry 再伪造取消。 */
        [[nodiscard]] auto IsStopping() const noexcept -> bool;
        [[nodiscard]] auto IsRetired() const noexcept -> bool override;
        /** @brief 正式 Run 一次消费根 lease；始终完成两个 scope 的真实 drain 后才决定结果。 */
        auto Run(Prism::Contract::MuxRootRequest Request)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override;
        /** @brief 暴露已有 child/frame/lifetime tree 的唯一协议活动 owner。 */
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override;
        /** @brief 显式取消根并发布取消结果。 */
        auto Cancel() noexcept -> void override;
        /** @brief 正常停止根并取消子活动，不把停止本身记为取消结果。 */
        auto Close() noexcept -> void override;
        /** @brief 冷绑定关闭后等本根已开始的正式 Run 真实完成，未开始的已关闭根不产生异步任务。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    private:
        /** @brief 供唯一静态 Create 分配正式执行 owner。 */
        explicit RootSession(
            std::shared_ptr<RootState> State,
            std::shared_ptr<RootRegistryNode> RegistrationNode);

        template<class Server>
        static auto ServeEngine(std::shared_ptr<RootState> State)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            auto Engine = std::make_shared<Server>();
            SessionOptions Options;
            Options.Registry = State->Loops;
            Options.Identity = State->Metadata.TaskIdentity;
            Options.MaxStreams = State->Options.MaxStreams;
            if (!Engine->Accept(State->Inbound, Options))
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            if (State->StreamCatalogOwner &&
                !State->StreamCatalogOwner->Enable(State->Options.MaxStreams))
            {
                State->StreamCatalogOwner->Disable();
            }
            if (!State->EngineControl)
                State->EngineControl = std::make_shared<EngineCloseOwner<Server>>(Engine, State);
            while (!State->Stopping.load())
            {
                const auto Stream = co_await Engine->AcceptStream();
                if (!Stream) break;
                const auto Typed = std::static_pointer_cast<StreamTransmission>(Stream);
                auto Child = std::make_shared<ChildState>();
                Child->Inbound = Stream;
                Child->Identity.StreamId = Prism::StreamId{Typed->Handle()->Id()};
                const auto Weak = std::weak_ptr<StreamTransmission>(Typed);
                Child->Reject = [Weak] { if (const auto Owner = Weak.lock()) Owner->Reset(); };
                Child->Reset = [Weak]() -> std::expected<void, Prism::Fault::Failure>
                {
                    if (const auto Owner = Weak.lock())
                    {
                        Owner->Reset();
                        return {};
                    }
                    return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                };
                Child->Finish = [Typed] { return Typed->DrainTerminations(); };
                if (!StartChild(State, std::move(Child)))
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::Canceled});
                }
            }
            State->Stop();
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        static auto RunHttp2(
            std::shared_ptr<RootState> State,
            std::shared_ptr<H2Mux::Http2Server> Server) -> Net::awaitable<void>;
        static auto ServeHttp2(std::shared_ptr<RootState> State)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        static auto Serve(std::shared_ptr<RootState> State)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        std::shared_ptr<RootState> State_;
        std::shared_ptr<RootActivity> Activity_;
        std::shared_ptr<RootRegistryNode> RegistrationNode_;
        bool CreateCommitted_{false};

        [[nodiscard]] static auto DrainResources(std::shared_ptr<RootState> State)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    };
}
