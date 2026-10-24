/** @file Writer.hpp @brief 64请求及4MiB自有分段缓冲writer，真实完成后归还租约。 */
#pragma once
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Transport/WriteDriver.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Foundation/Executor/FatalState.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/system/error_code.hpp>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <limits>
#include <span>
#include <boost/asio/strand.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/co_spawn.hpp>
namespace Prism::Transport
{
    /** @brief Input借用到completion返回；一次大请求只拥有一个64KiB块，保持请求之间的完整顺序。
     * @details 4MiB仅限制writer追加拥有的64块。完整借用源由调用者真实池预算与owner覆盖；
     * 合法16MiB输入逐块重填，不伪称首块预算已覆盖整个源，也不复制完整大消息。
     * Completion 按值转移进槽并持有到唯一一次交付；池租约（OwnedBytes）由该槽拥有，
     * 归还通知晚于用户 handler，块与槽在 native 回调对象真正退出后才释放。
     * 输出与错误：结果只有 IoResult{Bytes, Failure}，Bytes 是已真实交付的累计字节；
     * 封止后新请求与准入拒绝为 Canceled，64 数据槽耗尽为 ResourceUnavailable，关闭槽被
     * 占用为 WouldBlock，零进度为 WouldBlock，池租约失败原样保留其 Failure，driver 的原生
     * 错误保留首个 Terminal 及其 Native。取消、EOF、本地封止与底层错误四类不合并。
     * 取消：Cancel() 先封止整个写序列，再投递一次取消动作；它只 emit 当前 active 槽的
     * cancellation_signal，pending 槽随后各自完成一次 Canceled。Cancel 不关闭 driver，
     * 也不承诺墙钟时限；已部分写入的序列不会静默恢复。
     * 半关闭：WriteShutdown 作为第 65 控制槽排在全部先前 ticket 之后，成功只表示半关闭
     * 已下发；它不销毁读取方向，读取能力与最终关闭由 driver 及其底层决定。
     * 最终关闭者：Close() 只在没有任何 native 写回调在途时才向 driver 下发 Close，随后
     * co_spawn 的关闭协程等待 driver Activity()->Drain() 并保留晚到的 Failure；裸描述符的
     * 实际关闭者仍是底层 Transmission 载体，Writer 只负责按序交付并证明退栈。
     * executor：Writer 自身状态（ticket、槽顺序、关闭序列）固定在
     * make_strand(Driver->Executor()) 上，用户 completion 仍投递回其关联 executor，
     * Drain/Activity 报出的也是该 strand。
     * @note 未定义：Write() 直接调用 Submit 改写槽内非原子字段，而 Pump/Partial/Release 在
     * Writer 自有 strand 上执行，两个 strand 对象不同；多线程 io_context 下二者的并发排他性
     * 既无编译期也无运行期证明，留待 M13 与主会话构建验收决定。
     */
    class Writer final
    {
    public:
        using Completion = Prism::Transmission::Completion;
        using ControlResult = std::expected<void, Fault::Failure>;
    private:
        static constexpr std::size_t Capacity = 64, ChunkSize = 64U * 1024U;
        using ReturnSignal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;
        struct Slot final
        {
            std::atomic<bool> Used{false}, Ready{false}, Completed{false}, NativeActive{false};
            std::atomic<std::uint64_t> Ticket{0};
            std::span<const std::byte> Input;
            std::optional<Memory::OwnedBytes> Chunk;
            std::size_t Total{0}, Offset{0};
            Completion Handler;
            std::unique_ptr<ReturnSignal> Returned;
            Net::cancellation_signal Cancel;
            bool Canceled{false}, Entered{false};
        };
        struct State;
        /** @brief co_spawn真实关闭帧的完成owner；fatal原样发布，成功只发送预建原域归还通知。 */
        struct CloseCompletion final
        {
            using executor_type = Net::any_io_executor;
            using allocator_type = std::allocator<std::byte>;
            std::shared_ptr<State> Owner;
            bool Returned{false};
            explicit CloseCompletion(std::shared_ptr<State> Value);
            CloseCompletion(CloseCompletion&& Other) noexcept;
            ~CloseCompletion();
            [[nodiscard]] auto get_executor() const noexcept -> executor_type;
            [[nodiscard]] auto get_allocator() const noexcept -> allocator_type;
            auto operator()(std::exception_ptr Fatal, ControlResult Result) -> void;
        };
        struct CloseRetirement final
        {
            std::shared_ptr<State> Owner;
            bool Returned{false};
            explicit CloseRetirement(std::shared_ptr<State> Value);
            CloseRetirement(CloseRetirement&& Other) noexcept;
            ~CloseRetirement();
            auto operator()(boost::system::error_code Error) -> void;
        };
        struct Release final
        {
            std::shared_ptr<State> Owner;
            std::size_t Index;
            bool Returned{false};
            Release(std::shared_ptr<State> Value, std::size_t SlotIndex);
            Release(Release&& Other) noexcept;
            ~Release();
            auto operator()(boost::system::error_code Error) -> void;
        };
        class CompletionDelivery final : public Detail::AssociatedCompletion<Completion>
        {
        public:
            CompletionDelivery(std::shared_ptr<State> Owner, std::size_t Index, Completion Handler);
            CompletionDelivery(CompletionDelivery&& Other) noexcept;
            ~CompletionDelivery();
            auto operator()(IoResult Result) -> void;
        private:
            std::shared_ptr<State> Owner_;
            std::size_t Index_;
            bool Returned_{false};
        };
        enum class WakeKind { Pump, StopClose, StopCancel };
        struct Wake final
        {
            std::shared_ptr<State> Owner;
            bool Returned{false};
            WakeKind Kind{WakeKind::Pump};
            explicit Wake(std::shared_ptr<State> Value, WakeKind Action = WakeKind::Pump);
            Wake(Wake&& Other) noexcept;
            ~Wake();
            auto operator()() -> void;
        };
        struct CancelRequest final
        {
            std::weak_ptr<State> Owner;
            std::size_t Index;
            std::uint64_t Ticket;
            auto operator()(Net::cancellation_type Type) const -> void;
        };
        struct CancelAction final
        {
            std::shared_ptr<State> Owner;
            std::size_t Index;
            std::uint64_t Ticket;
            bool Returned{false};
            CancelAction(std::shared_ptr<State> Value, std::size_t Slot, std::uint64_t Number);
            CancelAction(CancelAction&& Other) noexcept;
            ~CancelAction();
            auto operator()() -> void;
        };
        class PartialCompletion final
        {
        public:
            using executor_type = Net::any_io_executor;
            /** @brief driver 的 native 操作状态可晚于用户 completion 退休；不用用户 erased 代理。 */
            using allocator_type = std::allocator<std::byte>;
            using cancellation_slot_type = Net::cancellation_slot;
            PartialCompletion(std::shared_ptr<State> Owner, std::size_t Index);
            PartialCompletion(PartialCompletion&& Other) noexcept;
            ~PartialCompletion();
            [[nodiscard]] auto get_executor() const noexcept -> executor_type;
            [[nodiscard]] auto get_allocator() const noexcept -> allocator_type;
            [[nodiscard]] auto get_cancellation_slot() const noexcept -> cancellation_slot_type;
            auto operator()(IoResult Result) -> void;
        private:
            std::shared_ptr<State> Owner_;
            std::size_t Index_;
            bool Returned_{false};
        };
        struct State final : Prism::Executor::ClosingResource, Prism::Contract::CarrierActivity, std::enable_shared_from_this<State>
        {
            State(std::shared_ptr<Memory::BytePool> Bytes, std::shared_ptr<WriteDriver> Port);
            std::shared_ptr<Memory::BytePool> Bytes;
            std::shared_ptr<WriteDriver> Driver;
            std::shared_ptr<Prism::Executor::ContextOwner> Context;
            std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
            std::shared_ptr<Prism::Executor::FatalState> Fatal;
            std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
            Lifecycle::DrainBarrier Barrier;
            Lifecycle::DrainBarrier Tasks;
            ReturnSignal CloseReturned;
            /** @brief 返回通知晚于用户完成，只使用State拥有的独立标准分配材料。 */
            std::allocator<std::byte> CleanupMemory;
            std::array<Slot, Capacity + 1> Slots;
            std::atomic<std::uint64_t> NextTicket{1};
            std::atomic<bool> Sealed{false}, Closing{false}, Blocked{false};
            std::optional<std::size_t> Active;
            Fault::Failure Terminal;
            std::atomic<bool> CloseEntered{false};
            std::atomic<bool> CloseIssued{false}, CloseConfirmed{false};
            Fault::FailureState RetainedFailure;
            auto Fail(Fault::Failure Error = {Fault::Code::Blocked}) noexcept -> void;
            [[nodiscard]] auto PostWake(WakeKind Kind) -> ControlResult;
            auto Notify() -> void;
            auto Submit(std::span<const std::byte> Input, Completion Handler, bool Shutdown) -> void;
            auto Pump() -> void;
            /** @brief Close受理后持有关闭预约，等待真实driver活动；归还通知不借用户allocator。 */
            auto BeginCloseDrain() -> void;
            [[nodiscard]] static auto AwaitClose(std::shared_ptr<Contract::CarrierActivity> Activity)
                -> Net::awaitable<ControlResult>;
            auto Partial(std::size_t Index, IoResult Result) -> void;
            auto Complete(std::size_t Index, IoResult Result) -> void;
            auto CancelSlot(std::size_t Index, std::uint64_t Ticket) -> void;
            [[nodiscard]] auto RequestCancel() -> ControlResult;
            [[nodiscard]] auto RequestClose() -> ControlResult;
            auto RequestRetirement() -> void override;
            auto Seal() noexcept -> void override;
            [[nodiscard]] auto Executor() const -> Net::any_io_executor override;
            [[nodiscard]] auto Drain() -> Net::awaitable<ControlResult> override;
            [[nodiscard]] static auto DrainState(std::shared_ptr<State> Owner)
                -> Net::awaitable<ControlResult>;
            auto Stop() -> bool;
            [[nodiscard]] auto IsRetired() const noexcept -> bool override;
            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override;
        };
    public:
        /** @brief 冷构造且显式注入真实共享池；不创建全局池或在热路径扩容。 */
        Writer(std::shared_ptr<Memory::BytePool> Bytes, std::shared_ptr<WriteDriver> Driver);
        /** @brief 大输入借用到completion，已交付字节在错误时保留；每请求只占一个64KiB块。 */
        auto Write(std::span<const std::byte> Input, Completion Handler) -> void;
        auto WriteShutdown(Completion Handler) -> void;
        /** @brief 封止并请求取消真实driver；实际active回调退出前不归还块或槽。 */
        [[nodiscard]] auto Close() -> ControlResult;
        [[nodiscard]] auto Cancel() -> ControlResult;
        [[nodiscard]] auto Drain() -> Net::awaitable<ControlResult>;
        [[nodiscard]] auto Activity() const -> std::shared_ptr<Prism::Contract::CarrierActivity>;
        /** @brief 原域排他冷移交使用真实预约计数，不能据此推断并发发起安全。 */
        [[nodiscard]] auto IsIdle() const noexcept -> bool;
    private:
        std::shared_ptr<State> State_;
    };
}
