/** @file MemoryStream.hpp @brief 同一strand上的有界内存流，统一IoResult和真实等待操作。 */
#pragma once
#include <Prism/Transport/Stream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/system/error_code.hpp>
#include <optional>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
namespace Prism
{
    /**
     * @brief 合成测试与基准用的有界内存流载体，成对端点在同一 strand 上互写有界队列。
     * @details 输入所有权：每个端点独占拥有自己的 State（shared_ptr），peer 只以 weak_ptr 引用；读写 span
     *          都只借用到该操作 completion，因为写在本端原域将字节复制进 peer 池的 OwnedBytes 租约、读把本地
     *          队首块复制到用户 buffer 后归还租约并唤醒 peer 的可写信号。每端 64 个 64KiB 块由自己的池发放，
     *          队列节点与租约一一对应，缩短逻辑长度不提前归还额度。
     *          输出与错误：唯一事实是 IoResult{Bytes, Failure}。本端已 Close 或本操作被取消交付 Canceled，
     *          对端半关闭交付 Eof，本端已 WriteShutdown 或 peer 已 Closed 交付 ConnectionAborted，后三类的
     *          Native 一律为空；只有真实 channel/timer 返回的原生错误才进入 Native。计时器正常到期
     *          返回 Timeout，其取消竞争读取产生的 operation_aborted 不是超时首因，不填入 Native。
     *          写方向队列满时等待 peer 腾空而不报 WouldBlock。
     *          取消：OnCancel 递增 CancelEpoch 并同时唤醒本端与 peer，在途的读/写循环在下一个检查点恰好交付
     *          一次 {0, Canceled}；可重复调用，取消不销毁已排队的块。
     *          半关闭：StartWriteShutdown 置本端 WriteClosed（后续写 ConnectionAborted）并置 peer 的 PeerEof
     *          （peer 读 Eof），本端读取方向完全保持可用；半关闭不关闭 State，也不关闭 peer。
     *          最终关闭者：OnClose 是唯一本层终态动作（置 Closed 并让 peer 见 EOF），没有裸描述符需要关闭；
     *          块与队列的物理释放由两端 shared_ptr 归零决定，peer 端已排队块的释放顺序不由本端 Close 规定。
     *          executor：State::Executor 是构造时 make_strand 得到的唯一域，MakeMemoryPair 让两端共享同一
     *          strand；Head/Tail/Count/Offset/PeerEof/WriteClosed/CancelEpoch/Timeout 为非原子成员，只能在
     *          该 strand 上变更，要求单一执行域，跨 strand 配对不受支持（私有构造仅友元 MakeMemoryPair）。
     * @note 未定义：本载体不参与真实网络，Close/Drain 与 Executor 的原域语义沿用 Transmission；SetTimeout
     *       只覆盖读方向，写方向的无界等待没有规定上界，留待 M13 决定。
     */
    class MemoryStream final : public Transmission
    {
    public:
        static constexpr std::chrono::milliseconds DefaultTimeout{0};
        /** @brief 成对端点共享一个strand，各自拥有64个64KiB块；取消/半关不销毁在途块。 */
        struct State final
        {
            explicit State(ExecutorType Executor);
            ExecutorType Executor;
            Net::experimental::channel<void(boost::system::error_code)> Readable, Writable;
            Memory::BytePool Pool;
            std::array<std::optional<Memory::OwnedBytes>, 64> Queue;
            std::size_t Head{0}, Tail{0}, Count{0}, Offset{0};
            std::uint64_t CancelEpoch{0};
            std::atomic<bool> Closed{false};
            bool PeerEof{false}, WriteClosed{false};
            std::chrono::milliseconds Timeout{DefaultTimeout};
        };
        explicit MemoryStream(ExecutorType Executor);
        [[nodiscard]] auto IsOpen() const -> bool override { return !In_->Closed.load(); }
        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override { In_->Timeout = Timeout; }
    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;
        auto StartWriteShutdown(Completion Handler) -> void override;
        [[nodiscard]] auto OnClose() -> ControlResult override;
        [[nodiscard]] auto OnCancel() -> ControlResult override;
    private:
        struct ReadInput;
        struct WriteInput;
        struct ReadOperation;
        struct WriteOperation;
        static auto Notify(const std::shared_ptr<State>& Value) -> void;
        [[nodiscard]] static auto Failure(boost::system::error_code Error) -> IoResult;
        MemoryStream(std::shared_ptr<State> Input, std::weak_ptr<State> Peer);
        std::shared_ptr<State> In_;
        std::weak_ptr<State> Peer_;
        friend auto MakeMemoryPair(ExecutorType) -> std::pair<MemoryStream, MemoryStream>;
    };
    [[nodiscard]] auto MakeMemoryPair(Net::any_io_executor Executor) -> std::pair<MemoryStream, MemoryStream>;
    static_assert(Stream<MemoryStream>);
}
