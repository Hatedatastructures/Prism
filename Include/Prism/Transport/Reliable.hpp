/** @file Reliable.hpp @brief 拥有TCP socket的typed I/O叶子，真实read与timer共同退出后才完成。 */
#pragma once
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <optional>
#include <cassert>
#include <chrono>
#include <span>
namespace Prism::Transport
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
        explicit Reliable(Net::any_io_executor Executor);
        explicit Reliable(SocketType Socket);
        /** @brief 连接参数按值拥有；真实connect和deadline均退出才返回，取消保留原生cause。 */
        auto Connect(const Net::ip::tcp::endpoint& Endpoint, std::chrono::milliseconds Timeout = std::chrono::seconds(5))
            -> Net::awaitable<ControlResult>;
        [[nodiscard]] auto TransportType() const noexcept -> Type override { return Type::Tcp; }
        [[nodiscard]] auto IsOpen() const -> bool override { return Socket_ && Socket_->is_open(); }
        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override { Timeout_ = Timeout; }
        [[nodiscard]] auto NativeSocket() noexcept -> SocketType& { assert(Socket_); return *Socket_; }
        [[nodiscard]] auto NativeSocket() const noexcept -> const SocketType& { assert(Socket_); return *Socket_; }
        /** @brief 仅在无I/O的冷移交点调用；固定executor不随socket移出失效。 */
        [[nodiscard]] auto ReleaseSocket() noexcept -> std::optional<SocketType>;
    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;
        auto StartWriteShutdown(Completion Handler) -> void override;
        [[nodiscard]] auto OnClose() -> ControlResult override;
        [[nodiscard]] auto OnCancel() -> ControlResult override;
    private:
        struct ConnectOptions;
        struct ConnectInput;
        struct ConnectOperation;
        struct ConnectWork;
        struct ConnectInitiation;
        class TimedRead;
        [[nodiscard]] static auto AwaitConnect(ConnectInitiation Initiation) -> Net::awaitable<ControlResult>;
        std::optional<SocketType> Socket_;
        std::chrono::milliseconds Timeout_{0};
    };
    [[nodiscard]] auto MakeReliable(const Net::any_io_executor& Executor) -> SharedTransmission;
    [[nodiscard]] auto MakeReliable(Net::ip::tcp::socket Socket) -> SharedTransmission;
}
