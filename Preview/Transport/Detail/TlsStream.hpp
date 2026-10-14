/** @file TlsStream.hpp @brief 唯一双向TLS engine owner，Asio ABI用于TLS客户端/服务端握手与数据。 */
#pragma once
#include <Preview/Transport/Connector.hpp>
#include <Preview/Transport/Detail/TlsOperations.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/detail/stream_core.hpp>
#include <boost/asio/ssl/detail/io.hpp>
#include <boost/asio/ssl/detail/handshake_op.hpp>
#include <boost/asio/ssl/detail/shutdown_op.hpp>
#include <tuple>
#include <type_traits>
namespace Preview::Transport::Detail
{
    /**
     * @brief 唯一的双向 TLS engine owner：引擎状态只在自己的 strand 上变更，完成一律异步交付。
     * @details 输入所有权：构造把 Connector 按值移入 Next_、把 strand 与 IoActivity 一并建出（:41-:42），
     *          ssl::context 只按引用借用并取 native_handle()（成员表 :188-:191 无 context 项），因此本类型
     *          不延长 context 生命周期；ReadSome/WriteSome 的 span 只借用到该次 completion（:51-:56），
     *          Handler 按值转移给 IoCompletion；next_layer/lowest_layer/native_handle 返回的皆是借用（:46-:49）。
     *          输出与错误：对象已销毁时 weak_from_this().lock() 得空 Owner，Initiation 以 {0, InvalidArgument}
     *          异步交付而绝不解引用 this（:170）；预约拒绝（封止、阻断、槽满）原样转交 IoActivity 的
     *          Failure（:172）；结果先由 StreamCompletion post 到用户的关联 executor 与 allocator（:116-:117），
     *          Asio ABI 入口再经 AbiCompletion 折回 error_code，Native 存在时保留原 category（:148-:151）。
     *          取消：排队前用 QueuedCompletion 建立 enable_total_cancellation 的子 slot 并取快照（:173-:174），
     *          Launch 在本域先检查快照，已取消则交付 {0, Canceled} 而不发起引擎操作（:135-:136）；真实 I/O
     *          已发起之后的取消由 Asio ssl io 经同一 slot 链执行，本类型不规定墙钟上限。
     *          半关闭：WriteShutdown 与 async_write_shutdown 只发本端 close_notify，读方向保持可用（:57-:58、
     *          :84-:90）；async_shutdown 走 Asio 的双向 shutdown_op，只有显式要求双向关闭者才使用（:77-:83）。
     *          最终关闭者：本类型没有 Cancel/Close 门面，从不关闭 socket；裸描述符的最终关闭属于 leaf
     *          Transmission（即 lowest_layer() 返回的那个引用，:48），控制命令由 TlsWriteDriver 转交。
     *          executor：Executor_ 是构造时 make_strand(Next_.get_executor()) 建立的单一 strand（:41、:45），
     *          全部引擎推进都 post 到该域后再 async_io（:177-:178、:138），因此 Core_（:190）可以非原子。
     * @note 未定义：context 由谁保活、engine 与 next_layer 之间的最终关闭次序，本文件内没有答案，须由
     *       装配层与关闭链卡决定；数据槽与控制槽的分界见 Reserve（:181-:186），其额度属 IoActivity 契约。
     */
    class TlsStream final : public std::enable_shared_from_this<TlsStream>
    {
    public:
        using executor_type = Net::any_io_executor;
        using lowest_layer_type = Preview::Transmission;
        TlsStream(Connector Next, Net::ssl::context& Context)
            : Next_(std::move(Next)), Executor_(Net::make_strand(Next_.get_executor())), Core_(Context.native_handle(), Executor_), Activity_(std::make_shared<IoActivity>(Executor_)) {}
        [[nodiscard]] auto Activity() const noexcept -> std::shared_ptr<Preview::Contract::CarrierActivity> { return Activity_; }
        [[nodiscard]] auto IsIdle() const noexcept -> bool { return Activity_->IsIdle(); }
        [[nodiscard]] auto get_executor() const noexcept -> executor_type { return Executor_; }
        [[nodiscard]] auto next_layer() noexcept -> Connector& { return Next_; }
        [[nodiscard]] auto next_layer() const noexcept -> const Connector& { return Next_; }
        [[nodiscard]] auto lowest_layer() noexcept -> Preview::Transmission& { return Next_.lowest_layer(); }
        [[nodiscard]] auto native_handle() noexcept -> SSL* { return Core_.engine_.native_handle(); }
        /** @brief 正式内部读保留领域失败和真实原生原因；缓冲借用到实际completion退出。 */
        auto ReadSome(std::span<std::byte> Input, IoCompletion Handler) -> void
        { Initiation<TlsDataOperation<Net::mutable_buffer, true>, false>{weak_from_this().lock(), Executor_,
            TlsDataOperation<Net::mutable_buffer, true>(Net::buffer(Input.data(), Input.size()))}(std::move(Handler)); }
        auto WriteSome(std::span<const std::byte> Input, IoCompletion Handler) -> void
        { Initiation<TlsDataOperation<Net::const_buffer, false>, false>{weak_from_this().lock(), Executor_,
            TlsDataOperation<Net::const_buffer, false>(Net::buffer(Input.data(), Input.size()))}(std::move(Handler)); }
        auto WriteShutdown(IoCompletion Handler) -> void
        { Initiation<TlsWriteShutdownOperation, false>{weak_from_this().lock(), Executor_, TlsWriteShutdownOperation{}}(std::move(Handler)); }
        template<class Buffers, class Token>
        auto async_read_some(const Buffers& Input, Token&& Handler)
        {
            return Net::async_initiate<Token, void(boost::system::error_code, std::size_t)>(
                Initiation<TlsDataOperation<Buffers, true>>{weak_from_this().lock(), Executor_, TlsDataOperation<Buffers, true>(Input)}, Handler);
        }
        template<class Buffers, class Token>
        auto async_write_some(const Buffers& Input, Token&& Handler)
        {
            return Net::async_initiate<Token, void(boost::system::error_code, std::size_t)>(
                Initiation<TlsDataOperation<Buffers, false>>{weak_from_this().lock(), Executor_, TlsDataOperation<Buffers, false>(Input)}, Handler);
        }
        template<class Token>
        auto async_handshake(Net::ssl::stream_base::handshake_type Side, Token&& Handler)
        {
            return Net::async_initiate<Token, void(boost::system::error_code)>(
                Initiation<SslDetail::handshake_op, true, false>{
                    weak_from_this().lock(), Executor_, SslDetail::handshake_op(Side)}, Handler);
        }
        /** @brief 完整TLS关闭ABI，仅显式请求双向关闭的客户端调用。 */
        template<class Token>
        auto async_shutdown(Token&& Handler)
        {
            return Net::async_initiate<Token, void(boost::system::error_code)>(
                Initiation<SslDetail::shutdown_op, true, false>{
                    weak_from_this().lock(), Executor_, SslDetail::shutdown_op{}}, Handler);
        }
        /** @brief 正式writer使用的单向close_notify操作；实际输出写完才通知。 */
        template<class Token>
        auto async_write_shutdown(Token&& Handler)
        {
            return Net::async_initiate<Token, void(boost::system::error_code)>(
                Initiation<TlsWriteShutdownOperation>{weak_from_this().lock(), Executor_, TlsWriteShutdownOperation{}}, Handler);
        }
    private:
        template<class Handler, class... Args>
        class Delivery final : public AssociatedCompletion<Handler>
        {
        public:
            Delivery(std::shared_ptr<TlsStream> Owner, Handler Callback, std::tuple<Args...> Result)
                : AssociatedCompletion<Handler>(std::move(Callback)), Owner_(std::move(Owner)), Result_(std::move(Result)) {}
            auto operator()() -> void { std::apply(std::move(this->Handler_), std::move(Result_)); }
        private:
            std::shared_ptr<TlsStream> Owner_;
            std::tuple<Args...> Result_;
        };
        template<class Handler>
        class StreamCompletion final : public AssociatedCompletion<Handler>
        {
        public:
            using executor_type = Net::any_io_executor;
            StreamCompletion(std::shared_ptr<TlsStream> Owner, Handler Callback)
                : AssociatedCompletion<Handler>(std::move(Callback)), Owner_(std::move(Owner)) {}
            [[nodiscard]] auto get_executor() const noexcept -> executor_type { return Owner_->Executor_; }
            template<class... Args>
            auto operator()(Args... Values) -> void
            {
                Net::post(Owner_->Executor_,
                    Delivery<Handler, Args...>(Owner_, std::move(this->Handler_),
                                                std::make_tuple(std::move(Values)...)));
            }
        private:
            std::shared_ptr<TlsStream> Owner_;
        };
        template<class Operation>
        struct Pending final { Operation Work; Net::cancellation_state Cancellation; };
        template<class Operation>
        struct Launch final : AssociatedCompletion<IoCompletion>
        {
            using executor_type = Net::any_io_executor;
            std::shared_ptr<TlsStream> Owner;
            Pending<Operation> Action;
            Launch(std::shared_ptr<TlsStream> Value, Pending<Operation> Work, IoCompletion Callback)
                : AssociatedCompletion<IoCompletion>(std::move(Callback)), Owner(std::move(Value)), Action(std::move(Work)) {}
            [[nodiscard]] auto get_executor() const noexcept -> executor_type { return Owner->Executor_; }
            auto operator()() -> void
            {
                if (Action.Cancellation.cancelled() != Net::cancellation_type::none)
                { PostResult(Owner->Executor_, std::move(this->Handler_), {0, {Fault::Code::Canceled}}); return; }
                auto Completion = StreamCompletion<NativeCompletion>(Owner, NativeCompletion(std::move(this->Handler_)));
                SslDetail::async_io(Owner->Next_, Owner->Core_, Action.Work, Completion);
            }
        };
        template<class Handler, bool IncludeBytes>
        class AbiCompletion final : public AssociatedCompletion<Handler>
        {
        public:
            explicit AbiCompletion(Handler Callback) : AssociatedCompletion<Handler>(std::move(Callback)) {}
            auto operator()(Preview::IoResult Result) -> void
            {
                const auto Error = ToAsioFailure(Result.Failure);
                if constexpr (IncludeBytes)
                {
                    if constexpr (std::is_invocable_v<Handler, boost::system::error_code, std::size_t>)
                        std::move(this->Handler_)(Error, Result.Bytes);
                    else
                        std::move(this->Handler_)(Error);
                }
                else
                {
                    std::move(this->Handler_)(Error);
                }
            }
        };
        template<class Operation, bool Abi = true, bool IncludeBytes = true>
        struct Initiation
        {
            std::shared_ptr<TlsStream> Owner;
            Net::any_io_executor Fallback;
            Operation Work;
            using executor_type = Net::any_io_executor;
            [[nodiscard]] auto get_executor() const noexcept -> executor_type { return Fallback; }
            template<class Handler>
            auto operator()(Handler&& Callback) -> void
            {
                const auto UserExecutor = Net::get_associated_executor(Callback, Fallback);
                auto Bound = Net::bind_executor(UserExecutor, std::forward<Handler>(Callback));
                IoCompletion Completion;
                if constexpr (Abi)
                    Completion = IoCompletion(
                        AbiCompletion<decltype(Bound), IncludeBytes>(std::move(Bound)));
                else Completion = IoCompletion(std::move(Bound));
                if (!Owner) { PostResult(Fallback, std::move(Completion), {0, {Fault::Code::InvalidArgument}}); return; }
                auto Reservation = Reserve();
                if (!Reservation) { PostResult(Fallback, std::move(Completion), {0, Reservation.error()}); return; }
                QueuedCompletion Queued(IoCompletion(TrackedCompletion(std::move(*Reservation), std::move(Completion))));
                const auto Cancellation = Queued.Cancellation();
                IoCompletion Tracked(std::move(Queued));
                const auto Allocator = Net::get_associated_allocator(Tracked);
                Net::post(Owner->Executor_, Net::bind_allocator(Allocator,
                    Launch<Operation>(Owner, Pending<Operation>{Work, Cancellation}, std::move(Tracked))));
            }
            /** @brief TLS关闭控制操作也独立于engine的数据槽，不在第二层重遇64数据额度。 */
            [[nodiscard]] auto Reserve() -> std::expected<IoActivity::Operation, Fault::Failure>
            {
                if constexpr (std::is_same_v<Operation, TlsWriteShutdownOperation> || std::is_same_v<Operation, SslDetail::shutdown_op>)
                    return Owner->Activity_->TryAcquireControl(Owner);
                return Owner->Activity_->TryAcquire(Owner);
            }
        };
        Connector Next_;
        executor_type Executor_;
        SslDetail::stream_core Core_;
        std::shared_ptr<IoActivity> Activity_;
    };
}
