/** @file TlsEngine.hpp @brief 双向 TLS engine 的私有 Asio 实现。 */
#pragma once
#include <Prism/Transport/Connector.hpp>
#include <Prism/Transport/Activity/Io.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Io/Completion.hpp>
#include <Prism/Transport/Detail/TlsOperations.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/associated_allocator.hpp>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/bind_allocator.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/ssl/detail/stream_core.hpp>
#include <boost/asio/ssl/detail/io.hpp>
#include <boost/asio/ssl/detail/handshake_op.hpp>
#include <boost/asio/ssl/detail/shutdown_op.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <openssl/ssl.h>
#include <span>
#include <tuple>
#include <type_traits>
#include <utility>
namespace Prism::Transport
{
    class TlsStream;
}
namespace Prism::Transport::Detail
{
    /** @brief TLS 一次性结果交付请求，Carrier 保活到最终 handler 退栈。 */
    struct TlsResultRequest final
    {
        Net::any_io_executor QueueExecutor;
        std::shared_ptr<TlsStream> Carrier;
        IoCompletion Handler;
        Prism::IoResult Result;
    };
    /** @brief TLS 异步结果先排入 engine executor，再由原 handler 的 associated executor 完成。 */
    auto PostTlsResult(TlsResultRequest Request) -> void;

    /**
     * @brief 唯一的双向 TLS engine owner：引擎状态只在自己的 strand 上变更，完成一律异步交付。
     * @details 输入所有权：构造按值接管 Connector 并借用 ssl::context；公开 facade 作为 Carrier 传入
     *          IoActivity，真实读写及关闭预约退出前始终保活本 engine 和底层 Transmission。
     *          输出与错误：typed IoResult 原样交付；Asio ABI 转换由 facade 的 completion adapter 执行。
     *          预约失败异步交付原 Failure，Native category/value 不折叠；Asio ABI 转换只由 public facade 负责。
     *          取消：排队前由 QueuedCompletion 建立 total-cancellation 子 slot 并保存快照；Launch 在本域
     *          检查快照，已取消则交付 Canceled，不发起 SSL 操作；真实 I/O 取消由 Asio SSL 操作完成。
     *          半关闭：TlsWriteShutdownOperation 只发本端 close_notify；完整 async_shutdown 使用 Asio shutdown_op。
     *          最终关闭者：本 engine 不关闭 socket；裸描述符由 lowest_layer 的 Transmission 关闭。
     *          executor：strand 从 Connector executor 建立；所有 engine 状态与 async_io 均在该 strand 推进。
     */
    class TlsEngine final
    {
    public:
        using executor_type = Net::any_io_executor;
        using lowest_layer_type = Prism::Transmission;
        TlsEngine(Connector Next, Net::ssl::context& Context);
        ~TlsEngine();
        [[nodiscard]] auto Activity() const noexcept -> std::shared_ptr<Prism::Contract::CarrierActivity>;
        [[nodiscard]] auto IsIdle() const noexcept -> bool;
        [[nodiscard]] auto get_executor() const noexcept -> executor_type;
        [[nodiscard]] auto next_layer() noexcept -> Connector&;
        [[nodiscard]] auto next_layer() const noexcept -> const Connector&;
        [[nodiscard]] auto lowest_layer() noexcept -> Prism::Transmission&;
        [[nodiscard]] auto native_handle() noexcept -> SSL*;
        auto ReadSome(std::shared_ptr<TlsStream> Carrier, std::span<std::byte> Input,
                      IoCompletion Handler) -> void;
        auto ReadSomeBound(std::shared_ptr<TlsStream> Carrier, std::span<std::byte> Input,
                           IoCompletion Handler) -> void;
        auto WriteSome(std::shared_ptr<TlsStream> Carrier, std::span<const std::byte> Input,
                       IoCompletion Handler) -> void;
        auto WriteSomeBound(std::shared_ptr<TlsStream> Carrier,
                            std::span<const std::byte> Input,
                            IoCompletion Handler) -> void;
        auto WriteShutdown(std::shared_ptr<TlsStream> Carrier, IoCompletion Handler) -> void;
        auto WriteShutdownBound(std::shared_ptr<TlsStream> Carrier,
                                IoCompletion Handler) -> void;
        auto Handshake(std::shared_ptr<TlsStream> Carrier,
                       Net::ssl::stream_base::handshake_type Side,
                       IoCompletion Handler) -> void;
        auto Shutdown(std::shared_ptr<TlsStream> Carrier, IoCompletion Handler) -> void;
    private:
        template<class Operation, bool ExecutorBound>
        auto Initiate(std::shared_ptr<TlsStream> Carrier, Operation Work,
                      IoCompletion Handler) -> void
        {
            Initiation<Operation, ExecutorBound>{
                this, std::move(Carrier), Executor_, std::move(Work)}
                (std::move(Handler));
        }

        template<class Handler, class... Args>
        class Delivery final : public AssociatedCompletion<Handler>
        {
        public:
            Delivery(std::shared_ptr<TlsStream> Carrier, Handler Callback, std::tuple<Args...> Result)
                : AssociatedCompletion<Handler>(std::move(Callback)), Carrier_(std::move(Carrier)), Result_(std::move(Result)) {}
            auto operator()() -> void { std::apply(std::move(this->Handler_), std::move(Result_)); }
        private:
            std::shared_ptr<TlsStream> Carrier_;
            std::tuple<Args...> Result_;
        };
        template<class Handler>
        class StreamCompletion final : public AssociatedCompletion<Handler>
        {
        public:
            using executor_type = Net::any_io_executor;
            StreamCompletion(TlsEngine* Owner, std::shared_ptr<TlsStream> Carrier, Handler Callback)
                : AssociatedCompletion<Handler>(std::move(Callback)), Owner_(Owner), Carrier_(std::move(Carrier)) {}
            [[nodiscard]] auto get_executor() const noexcept -> executor_type { return Owner_->Executor_; }
            template<class... Args>
            auto operator()(Args... Values) -> void
            {
                Net::post(Owner_->Executor_,
                    Delivery<Handler, Args...>(std::move(Carrier_),
                        std::move(this->Handler_), std::make_tuple(std::move(Values)...)));
            }
        private:
            TlsEngine* Owner_;
            std::shared_ptr<TlsStream> Carrier_;
        };
        template<class Operation>
        struct Pending final { Operation Work; Net::cancellation_state Cancellation; };
        /**
         * @brief 已预约 TLS 操作的排队所有权，Carrier 在 launch 退栈前保活对应 engine。
         */
        template<class Operation>
        struct LaunchRequest final
        {
            TlsEngine* Owner;
            std::shared_ptr<TlsStream> Carrier;
            Pending<Operation> Action;
        };
        template<class Operation>
        struct Launch final : AssociatedCompletion<IoCompletion>
        {
            using executor_type = Net::any_io_executor;
            Launch(LaunchRequest<Operation> Request, IoCompletion Callback)
                : AssociatedCompletion<IoCompletion>(std::move(Callback)),
                  Request_(std::move(Request)) {}
            [[nodiscard]] auto get_executor() const noexcept -> executor_type { return Request_.Owner->Executor_; }
            auto operator()() -> void
            {
                if (Request_.Action.Cancellation.cancelled() != Net::cancellation_type::none)
                {
                    const auto QueueExecutor = Request_.Owner->Executor_;
                    PostTlsResult({QueueExecutor, std::move(Request_.Carrier),
                        std::move(this->Handler_), {0, {Fault::Code::Canceled}}});
                    return;
                }
                auto Completion = StreamCompletion<NativeCompletion>(
                    Request_.Owner, Request_.Carrier, NativeCompletion(std::move(this->Handler_)));
                SslDetail::async_io(
                    Request_.Owner->Next_, Request_.Owner->Core_, Request_.Action.Work, Completion);
            }
        private:
            LaunchRequest<Operation> Request_;
        };
        template<class Operation, bool ExecutorBound>
        struct Initiation
        {
            TlsEngine* Owner;
            std::shared_ptr<TlsStream> Carrier;
            Net::any_io_executor Fallback;
            Operation Work;
            using executor_type = Net::any_io_executor;
            [[nodiscard]] auto get_executor() const noexcept -> executor_type { return Fallback; }
            auto operator()(IoCompletion Callback) -> void
            {
                IoCompletion Completion;
                if constexpr (ExecutorBound)
                    Completion = std::move(Callback);
                else
                {
                    const auto UserExecutor = Net::get_associated_executor(Callback, Fallback);
                    auto Bound = Net::bind_executor(UserExecutor, std::move(Callback));
                    Completion = IoCompletion(std::move(Bound));
                }
                if (!Carrier)
                {
                    PostTlsResult({Fallback, {}, std::move(Completion),
                        {0, {Fault::Code::InvalidArgument}}});
                    return;
                }
                auto Reservation = Reserve();
                if (!Reservation)
                {
                    PostTlsResult({Fallback, std::move(Carrier),
                        std::move(Completion), {0, Reservation.error()}});
                    return;
                }
                QueuedCompletion Queued(IoCompletion(TrackedCompletion(std::move(*Reservation), std::move(Completion))));
                auto Cancellation = Queued.Cancellation();
                IoCompletion Tracked(std::move(Queued));
                const auto Allocator = Net::get_associated_allocator(Tracked);
                Net::post(Owner->Executor_, Net::bind_allocator(Allocator,
                    Launch<Operation>(
                        LaunchRequest<Operation>{
                            Owner, std::move(Carrier),
                            Pending<Operation>{std::move(Work), std::move(Cancellation)}},
                        std::move(Tracked))));
            }
            /** @brief TLS关闭控制操作也独立于engine的数据槽，不在第二层重遇64数据额度。 */
            [[nodiscard]] auto Reserve() -> std::expected<IoActivity::Operation, Fault::Failure>
            {
                if constexpr (std::is_same_v<Operation, TlsWriteShutdownOperation> || std::is_same_v<Operation, SslDetail::shutdown_op>)
                    return Owner->Activity_->TryAcquireControl(Carrier);
                return Owner->Activity_->TryAcquire(Carrier);
            }
        };
        Connector Next_;
        executor_type Executor_;
        SslDetail::stream_core Core_;
        std::shared_ptr<IoActivity> Activity_;
    };
}
