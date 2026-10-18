/** @file Unreliable.hpp @brief UDP真实socket操作、来源过滤与统一typed结果。 */
#pragma once
#include <tuple>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/UnreliableEndpoint.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/as_tuple.hpp>
namespace Prism::Transport
{
    /**
     * @brief 拥有 UDP socket 的 Unreliable 叶子载体：datagram 收发、来源过滤与延迟域名解析。
     * @details 输入所有权：Executor 构造时本层拥有新建 socket，SocketType 构造时移动拥有已建 socket；
     *          Remote 端点按值拥有并在有值时启用来源过滤，无值时首个真实来源被捕获。收发 Buffer 与
     *          ReceiveFrom 的 Sender 输出引用都只借用到该操作 completion，调用方必须保活到完成；
     *          SendTo 的显式 Target 按值复制进操作帧。Connect/Bind 只在冷路径做语法解析与本端
     *          open/bind，域名解析延迟到实际操作内的异步 resolver，不同步访问 DNS。
     *          输出与错误：结果沿用 Transmission 的 IoResult{Bytes, Failure} 与 ControlResult；
     *          取消交付 Canceled，底层错误由 Fault::FromNative 保留 Native，WriteShutdown 之后的发送
     *          交付 ConnectionAborted 且 Native 为空，无目标地址交付 InvalidArgument，解析失败保留
     *          host_not_found 原生原因，接收超时交付 Timeout。UDP 无远端 EOF，本层不产生 Eof 类别。
     *          取消：OnCancel 调用 socket cancel，可重复且对已关闭 socket 直接成功；每次在途收发在
     *          取消后恰好完成一次，超时 timer 与 receive 由 parallel_group 等到两个完成源都退出才交付。
     *          半关闭：StartWriteShutdown 只置本层 WriteClosed 标记并同步完成后立即异步交付成功，
     *          读取方向继续可用；它不下发任何原生 shutdown，之后的发送一律 ConnectionAborted。
     *          最终关闭者：OnClose 的 socket close 是本叶子层唯一真实关闭点；上层 Close 成功只表示
     *          命令已交付原 executor，实际退栈须等待 Activity()->Drain()。
     *          executor：冷构造固定的原 executor 是唯一状态域，resolver 与超时 timer 都建在其上；
     *          Remote_/Host_/Port_/Filter_/Capture_/WriteClosed_/Sender_/Timeout_ 为非原子成员，
     *          要求单一执行域串行发起，跨线程并发调用未受保护。
     * @note 未定义：WriteShutdown 对 UDP 没有可下发的原生半关闭，读方向收到 EOF 的期望行为以及
     *       来源过滤持续丢包时是否应给出终态，均未在当前代码中确定，留待 M13 决定。
     */
    class Unreliable final : public Transmission
    {
    public:
        using SocketType = Net::ip::udp::socket;
        using EndpointType = Net::ip::udp::endpoint;
        explicit Unreliable(ExecutorType Executor, std::optional<EndpointType> Remote = {})
            : Transmission(Executor), Socket_(Executor), Remote_(std::move(Remote)), Filter_(Remote_.has_value()), Capture_(!Remote_) {}
        explicit Unreliable(SocketType Socket, std::optional<EndpointType> Remote = {})
            : Transmission(Socket.get_executor()), Socket_(std::move(Socket)), Remote_(std::move(Remote)), Filter_(Remote_.has_value()), Capture_(!Remote_) {}
        /**
         * @brief 借用远端文本完成冷配置；域名仅在实际异步操作中解析。
         * @details 成功拥有新目标，语法失败返回 InvalidArgument，关闭或打开失败保留原生错误。
         *          本操作同步执行且不能取消，不启动收发或半关闭；失败后的 socket 仍归本对象，
         *          调用方须沿 Close 与 Activity 退休。必须在原 executor 的串行状态域调用。
         */
        [[nodiscard]] auto Connect(const std::string& Text) -> ControlResult
        {
            const auto Target = Detail::ParseRemote(Text);
            if (!Target) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            boost::system::error_code Error;
            if (Socket_.is_open())
            {
                Socket_.close(Error);
                if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
            }
            Remote_.reset(); Host_.clear(); Port_ = 0; Filter_ = true; Capture_ = false;
            if (Target->Address)
            {
                EndpointType Endpoint(*Target->Address, Target->Port);
                Socket_.open(Endpoint.protocol(), Error);
                if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
                Remote_ = Endpoint;
            }
            else { Host_ = Target->Host; Port_ = Target->Port; }
            return {};
        }
        /**
         * @brief 按值接收端口并绑定本层 UDP socket；端口零由系统选择。
         * @details 成功切换为首包来源捕获，打开或绑定失败保留原生错误；同步且不能取消，
         *          不改变半关闭状态。失败资源仍归本对象，须由 Close 与 Activity 退休。
         *          必须在原 executor 的串行状态域调用。
         */
        [[nodiscard]] auto Bind(unsigned short Port) -> ControlResult
        {
            boost::system::error_code Error;
            if (!Socket_.is_open()) Socket_.open(Net::ip::udp::v4(), Error);
            if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
            Socket_.bind(EndpointType(Net::ip::udp::v4(), Port), Error);
            if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
            Remote_.reset(); Host_.clear(); Port_ = 0; Filter_ = false; Capture_ = true;
            return {};
        }
        [[nodiscard]] auto LocalEndpoint() const -> EndpointType
        { boost::system::error_code Error; auto Value = Socket_.local_endpoint(Error); if (Error) return {}; return Value; }
        [[nodiscard]] auto TransportType() const noexcept -> Type override { return Type::Udp; }
        [[nodiscard]] auto IsOpen() const -> bool override { return Socket_.is_open(); }
        [[nodiscard]] auto NativeSocket() noexcept -> SocketType& { return Socket_; }
        [[nodiscard]] auto NativeSocket() const noexcept -> const SocketType& { return Socket_; }
        auto SetRemote(const EndpointType& Endpoint) -> void
        { Remote_ = Endpoint; Host_.clear(); Port_ = 0; Filter_ = true; Capture_ = false; }
        auto AllowAnyPeer() noexcept -> void
        { Remote_.reset(); Host_.clear(); Port_ = 0; Filter_ = false; Capture_ = false; }
        [[nodiscard]] auto RemoteEndpoint() const noexcept -> std::optional<EndpointType> { return Remote_; }
        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override { Timeout_ = Timeout; }
        /** @brief Buffer与来源输出借用到completion；准入、取消和native完成均归同一activity。 */
        template<class Token>
        auto ReceiveFrom(std::span<std::byte> Buffer, EndpointType& Sender, Token&& Handler)
        { return Initiate(ReadInput{Self(), Buffer, &Sender}, std::forward<Token>(Handler)); }
        template<class Token>
        auto SendTo(std::span<const std::byte> Buffer, EndpointType Target, Token&& Handler)
        { return Initiate(WriteInput{Self(), Buffer, std::move(Target)}, std::forward<Token>(Handler)); }
        [[nodiscard]] auto ReceiveFrom(std::span<std::byte> Buffer, EndpointType& Sender) -> Net::awaitable<IoResult>;
        [[nodiscard]] auto SendTo(std::span<const std::byte> Buffer, EndpointType Target) -> Net::awaitable<IoResult>;
    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        { StartReceive(ReadInput{Self(), Buffer, &Sender_}, std::move(Handler)); }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        { StartSend(WriteInput{Self(), Buffer, {}}, std::move(Handler)); }
        auto StartWriteShutdown(Completion Handler) -> void override
        { WriteClosed_ = true; Detail::PostResult(Executor(), std::move(Handler), {}); }
        [[nodiscard]] auto OnClose() -> ControlResult override
        { boost::system::error_code Error; Socket_.close(Error); if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error))); return {}; }
        [[nodiscard]] auto OnCancel() -> ControlResult override
        { boost::system::error_code Error; if (Socket_.is_open()) Socket_.cancel(Error); if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error))); return {}; }
    private:
        struct ReadInput final { std::shared_ptr<Unreliable> Owner; std::span<std::byte> Buffer; EndpointType* Sender; };
        struct WriteInput final { std::shared_ptr<Unreliable> Owner; std::span<const std::byte> Buffer; std::optional<EndpointType> Target; };
        [[nodiscard]] auto Self() -> std::shared_ptr<Unreliable>
        { return std::static_pointer_cast<Unreliable>(weak_from_this().lock()); }
        template<class Input>
        struct Work final
        {
            Input Request;
            auto operator()(Completion Handler) -> void
            {
                if constexpr (std::is_same_v<Input, ReadInput>) Request.Owner->StartReceive(std::move(Request), std::move(Handler));
                else Request.Owner->StartSend(std::move(Request), std::move(Handler));
            }
        };
        template<class Input>
        struct Initiation
        {
            Input Request;
            ExecutorType Executor;
            template<class Handler>
            auto operator()(Handler&& Callback) -> void
            {
                const auto Associated = Net::get_associated_executor(Callback, Executor);
                Completion Bound(Net::bind_executor(Associated, std::forward<Handler>(Callback)));
                if (!Request.Owner) { Detail::PostResult(Executor, std::move(Bound), {0, {Fault::Code::InvalidArgument}}); return; }
                auto Owner = Request.Owner;
                Owner->StartOwned(Work<Input>{std::move(Request)}, std::move(Bound));
            }
        };
        template<class Input, class Token>
        auto Initiate(Input Request, Token&& Handler)
        { return Net::async_initiate<Token, void(IoResult)>(Initiation<Input>{std::move(Request), Executor()}, Handler); }
        template<class Input>
        [[nodiscard]] static auto AwaitDatagram(Input Request, ExecutorType Executor) -> Net::awaitable<IoResult>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            const auto Cancellation = co_await Net::this_coro::cancellation_state;
            if (!!Cancellation.cancelled()) co_return IoResult{0, {Fault::Code::Canceled}};
            auto Token = Net::use_awaitable;
            co_return co_await Net::async_initiate<decltype(Token), void(IoResult)>(
                Initiation<Input>{std::move(Request), std::move(Executor)}, Token);
        }
        struct ResolveOperation final
        {
            template<class State>
            auto operator()(State Operation, std::shared_ptr<Unreliable> Owner) const -> void
            {
                Detail::ConfigureIo(Operation);
                if (Owner->Remote_ || Owner->Host_.empty()) co_return std::tuple{boost::system::error_code{}};
                Net::ip::udp::resolver Resolver(Owner->Executor());
                auto [Error, Entries] = co_await Resolver.async_resolve(Owner->Host_, std::to_string(Owner->Port_), Net::as_tuple(Net::deferred));
                if (Error) co_return std::tuple{Error};
                for (const auto& Entry : Entries)
                {
                    Owner->Socket_.open(Entry.endpoint().protocol(), Error);
                    if (Error) continue;
                    Owner->Remote_ = Entry.endpoint(); Owner->Host_.clear(); Owner->Port_ = 0;
                    co_return std::tuple{boost::system::error_code{}};
                }
                if (!Error) Error = Net::error::host_not_found;
                co_return std::tuple{Error};
            }
        };
        template<class Token>
        auto Resolve(Token&& Handler)
        { return Net::async_initiate<Token, void(boost::system::error_code)>(Net::co_composed<void(boost::system::error_code)>(ResolveOperation{}, Executor()), Handler, Self()); }
        struct ReadOperation final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Detail::ConfigureIo(Operation);
                auto [Error] = co_await Input.Owner->Resolve(Net::as_tuple(Net::deferred));
                if (Error) co_return std::tuple{IoResult{0, Fault::FromNative(static_cast<std::error_code>(Error))}};
                while (true)
                {
                    auto [ReceiveError, Bytes] = co_await Input.Owner->Socket_.async_receive_from(
                        Net::buffer(Input.Buffer.data(), Input.Buffer.size()), *Input.Sender, Net::as_tuple(Net::deferred));
                    if (ReceiveError) co_return std::tuple{IoResult{Bytes, Fault::FromNative(static_cast<std::error_code>(ReceiveError))}};
                    if (Input.Owner->Filter_ && (!Input.Owner->Remote_ || *Input.Sender != *Input.Owner->Remote_)) continue;
                    if (Input.Owner->Capture_) { Input.Owner->Remote_ = *Input.Sender; Input.Owner->Filter_ = true; Input.Owner->Capture_ = false; }
                    co_return std::tuple{IoResult{Bytes, {}}};
                }
            }
        };
        struct WriteOperation final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Detail::ConfigureIo(Operation);
                if (Input.Owner->WriteClosed_) co_return std::tuple{IoResult{0, {Fault::Code::ConnectionAborted}}};
                if (!Input.Target)
                {
                    auto [Error] = co_await Input.Owner->Resolve(Net::as_tuple(Net::deferred));
                    if (Error) co_return std::tuple{IoResult{0, Fault::FromNative(static_cast<std::error_code>(Error))}};
                    Input.Target = Input.Owner->Remote_;
                }
                if (!Input.Target) co_return std::tuple{IoResult{0, {Fault::Code::InvalidArgument}}};
                auto [Error, Bytes] = co_await Input.Owner->Socket_.async_send_to(
                    Net::buffer(Input.Buffer.data(), Input.Buffer.size()), *Input.Target, Net::as_tuple(Net::deferred));
                co_return std::tuple{IoResult{Bytes, Fault::FromNative(static_cast<std::error_code>(Error))}};
            }
        };
        class TimedCompletion final : public Detail::AssociatedCompletion<Completion>
        {
        public:
            TimedCompletion(std::shared_ptr<Net::steady_timer> Timer, Completion Handler)
                : AssociatedCompletion(std::move(Handler)), Timer_(std::move(Timer)) {}
            auto operator()(std::array<std::size_t, 2> Order, IoResult Result, boost::system::error_code TimerError) -> void
            {
                if (Order[0] == 1 && !TimerError) Result.Failure.Code = Fault::Code::Timeout;
                std::move(Handler_)(Result);
            }
        private:
            std::shared_ptr<Net::steady_timer> Timer_;
        };
        auto StartReceive(ReadInput Input, Completion Handler) -> void
        {
            Completion Routed(Detail::OriginalCompletion(Executor(), std::move(Handler)));
            if (Timeout_.count() <= 0)
            { Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(ReadOperation{}, Executor()), Routed, std::move(Input)); return; }
            /** @brief timer实体寿命独立于用户erased handler；异步等待自身仍保留关联属性。 */
            auto Timer = std::make_shared<Net::steady_timer>(Executor());
            Timer->expires_after(Timeout_);
            auto Token = Net::deferred;
            auto Read = Net::async_initiate<Net::deferred_t, void(IoResult)>(
                Net::co_composed<void(IoResult)>(ReadOperation{}, Executor()), Token, std::move(Input));
            Net::experimental::make_parallel_group(std::move(Read), Timer->async_wait(Net::deferred))
                .async_wait(Net::experimental::wait_for_one(), TimedCompletion(std::move(Timer), std::move(Routed)));
        }
        auto StartSend(WriteInput Input, Completion Handler) -> void
        {
            Completion Routed(Detail::OriginalCompletion(Executor(), std::move(Handler)));
            Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(WriteOperation{}, Executor()), Routed, std::move(Input));
        }
        SocketType Socket_;
        std::optional<EndpointType> Remote_;
        std::string Host_;
        unsigned short Port_{0};
        bool Filter_{false}, Capture_{true}, WriteClosed_{false};
        EndpointType Sender_;
        std::chrono::milliseconds Timeout_{0};
    };
    inline auto Unreliable::ReceiveFrom(std::span<std::byte> Buffer, EndpointType& Sender) -> Net::awaitable<IoResult>
    { return AwaitDatagram(ReadInput{Self(), Buffer, &Sender}, Executor()); }
    inline auto Unreliable::SendTo(std::span<const std::byte> Buffer, EndpointType Target) -> Net::awaitable<IoResult>
    { return AwaitDatagram(WriteInput{Self(), Buffer, std::move(Target)}, Executor()); }
    [[nodiscard]] inline auto MakeUnreliable(const Net::any_io_executor& Executor, std::optional<Net::ip::udp::endpoint> Remote = {}) -> SharedTransmission
    { return std::make_shared<Unreliable>(Executor, std::move(Remote)); }
    [[nodiscard]] inline auto MakeUnreliable(Net::ip::udp::socket Socket, std::optional<Net::ip::udp::endpoint> Remote = {}) -> SharedTransmission
    { return std::make_shared<Unreliable>(std::move(Socket), std::move(Remote)); }
}
