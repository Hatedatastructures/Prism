/** @file Reliable.hpp @brief 拥有TCP socket的typed I/O叶子，真实read与timer共同退出后才完成。 */
#pragma once
#include <Preview/Transport/Transmission.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <optional>
#include <boost/asio/as_tuple.hpp>
#include <cassert>
namespace Preview::Transport
{
    /**
     * @brief 拥有 TCP socket 的 Reliable 叶子载体：typed 读写、连接期限与写半关闭的真实交付点。
     * @details 输入所有权：Executor 构造时本层拥有新建 socket，SocketType 构造时移动拥有已建 socket；
     *          Connect 的 endpoint 与 timeout 按值复制进操作帧，读写 span 只借用到该操作 completion。
     *          ReleaseSocket() 把 socket 所有权整体移出给冷移交调用方，此后本层 IsOpen 为假、
     *          读写一律 InvalidArgument，它只在无在途预约的移交点使用，不授权并发发起。
     *          输出与错误：Connect 返回 awaitable<ControlResult>，数据面返回 IoResult{Bytes, Failure}。
     *          远端 EOF 映射为 Fault::Code::Eof，取消为 Canceled，其余底层错误由 Fault::FromNative 保留
     *          Native 原 category/value；deadline 到期只改写领域 Code 为 Timeout 而不抹掉原生原因。
     *          取消：OnCancel 调用 socket cancel，可重复且对未打开的 socket 直接成功；进行中的 read/write
     *          在取消后恰好完成一次并保留已交付字节。设了 Timeout_ 的读由 parallel_group 等到 native
     *          读与 timer 两个完成源都退出后才交付，超时不提前宣称操作已消失。
     *          半关闭：StartWriteShutdown 只下发 shutdown_send，写方向封止而读取方向继续可用，其自身的
     *          原生错误同样经 FromNative 交付；半关闭不是最终关闭，之后仍可 Close。
     *          最终关闭者：本层 OnClose 的 socket close 是这条链上唯一真正释放描述符的地方，Connect 的
     *          失败与超时路径也在此关闭；上层 Close 成功只表示命令已交付原 executor，真实退出须等待
     *          Activity()->Drain()。
     *          executor：冷构造固定的 socket executor 是唯一状态域，Socket_ 与 Timeout_ 为非原子成员，
     *          SetTimeout 与所有 Start* 必须在同一执行域串行调用。
     */
    class Reliable final : public Transmission
    {
    public:
        using SocketType = Net::ip::tcp::socket;
        explicit Reliable(Net::any_io_executor Executor) : Transmission(Executor), Socket_(Executor) {}
        explicit Reliable(SocketType Socket) : Transmission(Socket.get_executor()), Socket_(std::move(Socket)) {}
        /** @brief 连接参数按值拥有；真实connect和deadline均退出才返回，取消保留原生cause。 */
        auto Connect(const Net::ip::tcp::endpoint& Endpoint, std::chrono::milliseconds Timeout = std::chrono::seconds(5))
            -> Net::awaitable<ControlResult>
        { return AwaitConnect(ConnectInitiation{std::static_pointer_cast<Reliable>(weak_from_this().lock()), {Endpoint, Timeout}, Executor()}); }
        [[nodiscard]] auto TransportType() const noexcept -> Type override { return Type::Tcp; }
        [[nodiscard]] auto IsOpen() const -> bool override { return Socket_ && Socket_->is_open(); }
        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override { Timeout_ = Timeout; }
        [[nodiscard]] auto NativeSocket() noexcept -> SocketType& { assert(Socket_); return *Socket_; }
        [[nodiscard]] auto NativeSocket() const noexcept -> const SocketType& { assert(Socket_); return *Socket_; }
        /** @brief 仅在无I/O的冷移交点调用；固定executor不随socket移出失效。 */
        [[nodiscard]] auto ReleaseSocket() noexcept -> std::optional<SocketType>
        { auto Result = std::move(Socket_); Socket_.reset(); return Result; }
    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (!Socket_) { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            if (Timeout_.count() <= 0)
            { Socket_->async_read_some(Net::buffer(Buffer.data(), Buffer.size()), Detail::NativeCompletion(std::move(Handler))); return; }
            /** @brief timer实体可晚于用户handler析构，使用独立标准分配材料；native关联仍透传。 */
            auto Timer = std::make_shared<Net::steady_timer>(Executor());
            Timer->expires_after(Timeout_);
            Net::experimental::make_parallel_group(
                Socket_->async_read_some(Net::buffer(Buffer.data(), Buffer.size()), Net::deferred),
                Timer->async_wait(Net::deferred))
                .async_wait(Net::experimental::wait_for_one(), Net::as_tuple(TimedRead(std::move(Timer), std::move(Handler))));
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!Socket_) { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            Socket_->async_write_some(Net::buffer(Buffer.data(), Buffer.size()), Detail::NativeCompletion(std::move(Handler)));
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            boost::system::error_code Error;
            if (!Socket_) { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            Socket_->shutdown(SocketType::shutdown_send, Error);
            Detail::PostResult(Executor(), std::move(Handler), {0, Fault::FromNative(static_cast<std::error_code>(Error))});
        }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            boost::system::error_code Error;
            if (Socket_) Socket_->close(Error);
            if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
            return {};
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            boost::system::error_code Error;
            if (Socket_ && Socket_->is_open()) Socket_->cancel(Error);
            if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
            return {};
        }
    private:
        struct ConnectOptions final { Net::ip::tcp::endpoint Endpoint; std::chrono::milliseconds Timeout; };
        struct ConnectInput final { std::shared_ptr<Reliable> Owner; ConnectOptions Options; };
        struct ConnectOperation final
        {
            template<class State>
            auto operator()(State Operation, ConnectInput Input) const -> void
            {
                Detail::ConfigureIo(Operation);
                if (!Input.Owner->Socket_) co_return std::tuple{IoResult{0, {Fault::Code::InvalidArgument}}};
                Net::steady_timer Timer(Input.Owner->Executor());
                if (Input.Options.Timeout.count() <= 0) Timer.expires_at((Net::steady_timer::time_point::max)());
                else Timer.expires_after(Input.Options.Timeout);
                auto [Order, Error, TimerError] = co_await Net::experimental::make_parallel_group(
                    Input.Owner->Socket_->async_connect(Input.Options.Endpoint, Net::deferred), Timer.async_wait(Net::deferred))
                    .async_wait(Net::experimental::wait_for_one(), Net::deferred);
                auto Failure = Fault::FromNative(static_cast<std::error_code>(Error));
                if (Order[0] == 1 && !TimerError) Failure.Code = Fault::Code::Timeout;
                if (Failure.Failed()) { boost::system::error_code CloseError; Input.Owner->Socket_->close(CloseError); }
                co_return std::tuple{IoResult{0, Failure}};
            }
        };
        struct ConnectWork final
        {
            ConnectInput Input;
            auto operator()(Completion Handler) -> void
            {
                const auto Executor = Input.Owner->Executor();
                Completion Routed(Detail::OriginalCompletion(Executor, std::move(Handler)));
                Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(ConnectOperation{}, Executor),
                    Routed, std::move(Input));
            }
        };
        struct ConnectInitiation final
        {
            std::shared_ptr<Reliable> Owner;
            ConnectOptions Options;
            ExecutorType Executor;
            template<class Handler>
            auto operator()(Handler&& Callback) -> void
            {
                const auto Domain = Net::get_associated_executor(Callback, Executor);
                Completion Bound(Net::bind_executor(Domain, std::forward<Handler>(Callback)));
                if (!Owner) { Detail::PostResult(Executor, std::move(Bound), {0, {Fault::Code::InvalidArgument}}); return; }
                Owner->StartOwned(ConnectWork{{Owner, Options}}, std::move(Bound));
            }
        };
        [[nodiscard]] static auto AwaitConnect(ConnectInitiation Initiation) -> Net::awaitable<ControlResult>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            const auto Cancellation = co_await Net::this_coro::cancellation_state;
            if (!!Cancellation.cancelled()) co_return std::unexpected(Fault::Failure{Fault::Code::Canceled});
            auto Token = Net::use_awaitable;
            const auto Result = co_await Net::async_initiate<decltype(Token), void(IoResult)>(std::move(Initiation), Token);
            if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
            co_return ControlResult{};
        }
        /** @brief parallel_group已等待timer和socket双完成；超时保留socket最后交付的字节。 */
        class TimedRead final : public Detail::AssociatedCompletion<Completion>
        {
        public:
            TimedRead(std::shared_ptr<Net::steady_timer> Timer, Completion Handler)
                : AssociatedCompletion(std::move(Handler)), Timer_(std::move(Timer)) {}
            auto operator()(std::tuple<std::array<std::size_t, 2>, boost::system::error_code,
                std::size_t, boost::system::error_code> Result) -> void
            {
                auto [Order, Error, Bytes, TimerError] = Result;
                auto Failure = Fault::FromNative(static_cast<std::error_code>(Error));
                if (Order[0] == 1 && !TimerError) Failure.Code = Fault::Code::Timeout;
                std::move(Handler_)(IoResult{Bytes, Failure});
            }
        private:
            std::shared_ptr<Net::steady_timer> Timer_;
        };
        std::optional<SocketType> Socket_;
        std::chrono::milliseconds Timeout_{0};
    };
    [[nodiscard]] inline auto MakeReliable(const Net::any_io_executor& Executor) -> SharedTransmission
    { return std::make_shared<Reliable>(Executor); }
    [[nodiscard]] inline auto MakeReliable(Net::ip::tcp::socket Socket) -> SharedTransmission
    { return std::make_shared<Reliable>(std::move(Socket)); }
}
