/** @file Unreliable.hpp @brief UDP真实socket操作、来源过滤与统一typed结果。 */
#pragma once
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/associated_executor.hpp>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
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
        explicit Unreliable(ExecutorType Executor, std::optional<EndpointType> Remote = {});
        explicit Unreliable(SocketType Socket, std::optional<EndpointType> Remote = {});
        /**
         * @brief 借用远端文本完成冷配置；域名仅在实际异步操作中解析。
         * @details 成功拥有新目标，语法失败返回 InvalidArgument，关闭或打开失败保留原生错误。
         *          本操作同步执行且不能取消，不启动收发或半关闭；失败后的 socket 仍归本对象，
         *          调用方须沿 Close 与 Activity 退休。必须在原 executor 的串行状态域调用。
         */
        [[nodiscard]] auto Connect(const std::string& Text) -> ControlResult;
        /**
         * @brief 按值接收端口并绑定本层 UDP socket；端口零由系统选择。
         * @details 成功切换为首包来源捕获，打开或绑定失败保留原生错误；同步且不能取消，
         *          不改变半关闭状态。失败资源仍归本对象，须由 Close 与 Activity 退休。
         *          必须在原 executor 的串行状态域调用。
         */
        [[nodiscard]] auto Bind(unsigned short Port) -> ControlResult;
        /** @brief 查询当前本地绑定端点；socket 查询失败返回默认端点。 */
        [[nodiscard]] auto LocalEndpoint() const -> EndpointType;
        [[nodiscard]] auto TransportType() const noexcept -> Type override { return Type::Udp; }
        [[nodiscard]] auto IsOpen() const -> bool override { return Socket_.is_open(); }
        [[nodiscard]] auto NativeSocket() noexcept -> SocketType& { return Socket_; }
        [[nodiscard]] auto NativeSocket() const noexcept -> const SocketType& { return Socket_; }
        auto SetRemote(const EndpointType& Endpoint) -> void;
        auto AllowAnyPeer() noexcept -> void;
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
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;
        auto StartWriteShutdown(Completion Handler) -> void override;
        [[nodiscard]] auto OnClose() -> ControlResult override;
        [[nodiscard]] auto OnCancel() -> ControlResult override;
    private:
        struct ReadInput final { std::shared_ptr<Unreliable> Owner; std::span<std::byte> Buffer; EndpointType* Sender; };
        struct WriteInput final { std::shared_ptr<Unreliable> Owner; std::span<const std::byte> Buffer; std::optional<EndpointType> Target; };
        struct ResolveOperation;
        struct ReadOperation;
        struct WriteOperation;
        class TimedCompletion;
        [[nodiscard]] auto Self() -> std::shared_ptr<Unreliable>;
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
                if (!Request.Owner) { Prism::Transmission::PostResult(Executor, std::move(Bound), {0, {Fault::Code::InvalidArgument}}); return; }
                auto Owner = Request.Owner;
                Owner->StartOwned(Work<Input>{std::move(Request)}, std::move(Bound));
            }
        };
        template<class Input, class Token>
        auto Initiate(Input Request, Token&& Handler)
        { return Net::async_initiate<Token, void(IoResult)>(Initiation<Input>{std::move(Request), Executor()}, Handler); }
        template<class Input>
        [[nodiscard]] static auto AwaitDatagram(Input Request, ExecutorType Executor) -> Net::awaitable<IoResult>;
        template<class Token>
        auto Resolve(Token&& Handler);
        auto StartReceive(ReadInput Input, Completion Handler) -> void;
        auto StartSend(WriteInput Input, Completion Handler) -> void;
        SocketType Socket_;
        std::optional<EndpointType> Remote_;
        std::string Host_;
        unsigned short Port_{0};
        bool Filter_{false}, Capture_{true}, WriteClosed_{false};
        EndpointType Sender_;
        std::chrono::milliseconds Timeout_{0};
    };
    [[nodiscard]] auto MakeUnreliable(const Net::any_io_executor& Executor, std::optional<Net::ip::udp::endpoint> Remote = {}) -> SharedTransmission;
    [[nodiscard]] auto MakeUnreliable(Net::ip::udp::socket Socket, std::optional<Net::ip::udp::endpoint> Remote = {}) -> SharedTransmission;
}
