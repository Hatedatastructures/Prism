/** @file Writer.hpp @brief 64请求及4MiB自有分段缓冲writer，真实完成后归还租约。 */
#pragma once
#include <Prism/Transport/WriteDriver.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Foundation/Executor/FatalState.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <limits>
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
        using Completion = Detail::IoCompletion;
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
            explicit CloseCompletion(std::shared_ptr<State> Value) : Owner(std::move(Value)) {}
            CloseCompletion(CloseCompletion&& Other) noexcept
                : Owner(std::move(Other.Owner)), Returned(Other.Returned) {}
            ~CloseCompletion();
            [[nodiscard]] auto get_executor() const noexcept -> executor_type;
            [[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return {}; }
            auto operator()(std::exception_ptr Fatal, ControlResult Result) -> void;
        };
        struct CloseRetirement final
        {
            std::shared_ptr<State> Owner;
            bool Returned{false};
            explicit CloseRetirement(std::shared_ptr<State> Value) : Owner(std::move(Value)) {}
            CloseRetirement(CloseRetirement&& Other) noexcept : Owner(std::move(Other.Owner)), Returned(Other.Returned) {}
            ~CloseRetirement();
            auto operator()(boost::system::error_code Error) -> void;
        };
        struct Release final
        {
            std::shared_ptr<State> Owner;
            std::size_t Index;
            bool Returned{false};
            Release(std::shared_ptr<State> Value, std::size_t SlotIndex) : Owner(std::move(Value)), Index(SlotIndex) {}
            Release(Release&& Other) noexcept : Owner(std::move(Other.Owner)), Index(Other.Index) {}
            ~Release();
            auto operator()(boost::system::error_code Error) -> void;
        };
        class CompletionDelivery final : public Detail::AssociatedCompletion<Completion>
        {
        public:
            CompletionDelivery(std::shared_ptr<State> Owner, std::size_t Index, Completion Handler)
                : AssociatedCompletion(std::move(Handler)), Owner_(std::move(Owner)), Index_(Index) {}
            CompletionDelivery(CompletionDelivery&& Other) noexcept
                : AssociatedCompletion(std::move(Other.Handler_)), Owner_(std::move(Other.Owner_)), Index_(Other.Index_), Returned_(Other.Returned_) {}
            ~CompletionDelivery();
            auto operator()(IoResult Result) -> void { std::move(Handler_)(Result); Returned_ = true; }
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
            explicit Wake(std::shared_ptr<State> Value, WakeKind Action = WakeKind::Pump) : Owner(std::move(Value)), Kind(Action) {}
            Wake(Wake&& Other) noexcept : Owner(std::move(Other.Owner)), Kind(Other.Kind) {}
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
            CancelAction(std::shared_ptr<State> Value, std::size_t Slot, std::uint64_t Number)
                : Owner(std::move(Value)), Index(Slot), Ticket(Number) {}
            CancelAction(CancelAction&& Other) noexcept
                : Owner(std::move(Other.Owner)), Index(Other.Index), Ticket(Other.Ticket) {}
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
            PartialCompletion(PartialCompletion&& Other) noexcept : Owner_(std::move(Other.Owner_)), Index_(Other.Index_), Returned_(Other.Returned_) {}
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
            State(std::shared_ptr<Memory::BytePool> Bytes, std::shared_ptr<WriteDriver> Port)
                : Bytes(std::move(Bytes)), Driver(std::move(Port)),
                  Context(Prism::Executor::ContextOwner::Find(Driver->Executor())),
                  Storage(Prism::Executor::ContextOwner::Storage(Driver->Executor())),
                  Fatal(Prism::Executor::FatalState::For(Driver->Executor())),
                  Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(Net::make_strand(Driver->Executor()))),
                  Barrier(Reclaimer), Tasks(Reclaimer), CloseReturned(Reclaimer->Executor(), 1)
            { for (auto& Entry : Slots) Entry.Returned = std::make_unique<ReturnSignal>(Reclaimer->Executor(), 1); }
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
            auto Fail(Fault::Failure Error = {Fault::Code::Blocked}) noexcept -> void
            {
                if (RetainedFailure.TrySet(Error)) { Blocked.store(true, std::memory_order_release); Barrier.Block(); Tasks.Block(); }
                Storage->Retain(shared_from_this());
            }
            [[nodiscard]] auto PostWake(WakeKind Kind) -> ControlResult
            {
                if (!Tasks.Enter()) return std::unexpected(RetainedFailure.Load());
                auto Result = Reclaimer->Post(Wake(shared_from_this(), Kind));
                if (!Result) Fail(Result.error());
                return Result;
            }
            auto Notify() -> void { (void)PostWake(WakeKind::Pump); }
            auto Submit(std::span<const std::byte> Input, Completion Handler, bool Shutdown) -> void
            {
                std::size_t Index = Capacity;
                if (!Shutdown)
                {
                    if (Sealed.load()) { Detail::PostResult(Reclaimer->Executor(), std::move(Handler), {0, {Fault::Code::Canceled}}); return; }
                    for (Index = 0; Index < Capacity; ++Index) if (!Slots[Index].Used.exchange(true)) break;
                    if (Index == Capacity) { Detail::PostResult(Reclaimer->Executor(), std::move(Handler), {0, {Fault::Code::ResourceUnavailable}}); return; }
                }
                else
                {
                    if (Slots[Index].Used.exchange(true)) { Detail::PostResult(Reclaimer->Executor(), std::move(Handler), {0, {Fault::Code::WouldBlock}}); return; }
                    Sealed.store(true);
                }
                auto& Entry = Slots[Index];
                Entry.Handler = std::move(Handler);
                Entry.Input = Input;
                Entry.Ticket.store(NextTicket.fetch_add(1));
                Entry.Total = 0; Entry.Offset = 0; Entry.Canceled = false; Entry.Entered = false; Entry.Completed.store(false);
                if (!Barrier.Enter())
                {
                    auto Refused = std::move(Entry.Handler);
                    Entry.Input = {};
                    Entry.Used.store(false, std::memory_order_release);
                    Detail::PostResult(Reclaimer->Executor(), std::move(Refused), {0, {Fault::Code::Canceled}});
                    return;
                }
                Entry.Entered = true;
                Entry.Returned->async_receive(Net::bind_allocator(CleanupMemory,
                    Net::bind_executor(Reclaimer->Executor(), Release(shared_from_this(), Index))));
                if (!Shutdown && Sealed.load()) { Complete(Index, {0, {Fault::Code::Canceled}}); return; }
                if (!Input.empty())
                {
                    if (!Bytes || Bytes->BlockSize() != ChunkSize)
                    { Complete(Index, {0, {Fault::Code::InvalidArgument}}); return; }
                    auto Lease = Bytes->TryAcquire((std::min)(Input.size(), ChunkSize));
                    if (!Lease) { Complete(Index, {0, Lease.error()}); return; }
                    Entry.Chunk.emplace(std::move(*Lease));
                    std::memcpy(Entry.Chunk->WritableBytes().data(), Input.data(), Entry.Chunk->Size());
                }
                auto Cancel = Net::get_associated_cancellation_slot(Entry.Handler);
                if (Cancel.is_connected()) Cancel.assign(CancelRequest{shared_from_this(), Index, Entry.Ticket.load()});
                Entry.Ready.store(true, std::memory_order_release);
                Notify();
            }
            auto Pump() -> void
            {
                if (Active) return;
                if (Closing.load() && !CloseIssued)
                {
                    for (const auto& Entry : Slots) if (Entry.NativeActive.load()) return;
                    const auto Result = Driver->Close();
                    if (!Result) { Fail(Result.error()); return; }
                    CloseIssued = true;
                    BeginCloseDrain();
                }
                std::optional<std::size_t> Selected;
                auto Ticket = (std::numeric_limits<std::uint64_t>::max)();
                for (std::size_t Index = 0; Index <= Capacity; ++Index)
                {
                    const auto& Entry = Slots[Index];
                    if (!Entry.Used.load() || Entry.Completed.load()) continue;
                    if (!Entry.Ready.load()) return;
                    if (Entry.Ticket.load() < Ticket) { Ticket = Entry.Ticket.load(); Selected = Index; }
                }
                if (!Selected) return;
                const auto Index = *Selected;
                auto& Entry = Slots[Index];
                if (Terminal.Failed()) { Complete(Index, {Entry.Total, Terminal}); Notify(); return; }
                if (Entry.Canceled) { Complete(Index, {Entry.Total, {Fault::Code::Canceled}}); Notify(); return; }
                Active = Index;
                Entry.NativeActive.store(true);
                if (Index == Capacity) { Driver->WriteShutdown(PartialCompletion(shared_from_this(), Index)); return; }
                if (Entry.Input.empty()) { Entry.NativeActive.store(false); Active.reset(); Complete(Index, {}); Notify(); return; }
                Driver->WritePartial(Entry.Chunk->Bytes().subspan(Entry.Offset), PartialCompletion(shared_from_this(), Index));
            }
            /** @brief Close受理后持有关闭预约，等待真实driver活动；归还通知不借用户allocator。 */
            auto BeginCloseDrain() -> void
            {
                auto Activity = Driver->Activity();
                if (!Activity) { Fail({Fault::Code::InvalidArgument}); return; }
                CloseReturned.async_receive(Net::bind_allocator(CleanupMemory,
                    Net::bind_executor(Reclaimer->Executor(), CloseRetirement(shared_from_this()))));
                Net::co_spawn(Reclaimer->Executor(), AwaitClose(std::move(Activity)), CloseCompletion(shared_from_this()));
            }
            [[nodiscard]] static auto AwaitClose(std::shared_ptr<Contract::CarrierActivity> Activity)
                -> Net::awaitable<ControlResult>
            {
                co_await Net::this_coro::throw_if_cancelled(false);
                const auto Result = co_await Activity->Drain();
                if (!Result) co_return std::unexpected(Result.error());
                if (!Activity->IsRetired())
                    co_return std::unexpected(Fault::Failure{Fault::Code::Blocked});
                co_return ControlResult{};
            }
            auto Partial(std::size_t Index, IoResult Result) -> void
            {
                auto& Entry = Slots[Index];
                if (Index != Capacity)
                {
                    const auto Remaining = Entry.Chunk->Size() - Entry.Offset;
                    if (Result.Bytes > Remaining) { Result.Bytes = 0; Result.Failure.Code = Fault::Code::InvalidArgument; }
                    Entry.Total += Result.Bytes;
                    Entry.Offset += Result.Bytes;
                }
                if (Result.Failure.Failed())
                { if (Terminal.Succeeded() || !Terminal.Native) Terminal = Result.Failure; Sealed.store(true); }
                if (Entry.Canceled && !Terminal.Failed()) { Terminal = {Fault::Code::Canceled}; Sealed.store(true); }
                if (Terminal.Failed() || Index == Capacity || Entry.Total == Entry.Input.size())
                { Active.reset(); Complete(Index, {Entry.Total, Terminal}); Notify(); return; }
                if (Result.Bytes == 0)
                { Terminal = {Fault::Code::WouldBlock}; Active.reset(); Complete(Index, {Entry.Total, Terminal}); Notify(); return; }
                if (Entry.Offset == Entry.Chunk->Size())
                {
                    const auto Size = (std::min)(Entry.Input.size() - Entry.Total, ChunkSize);
                    const auto Resized = Entry.Chunk->Resize(Size);
                    if (!Resized) { Terminal = Resized.error(); Active.reset(); Complete(Index, {Entry.Total, Terminal}); Notify(); return; }
                    std::memcpy(Entry.Chunk->WritableBytes().data(), Entry.Input.data() + Entry.Total, Size);
                    Entry.Offset = 0;
                }
                Active.reset();
                Notify();
            }
            auto Complete(std::size_t Index, IoResult Result) -> void
            {
                auto& Entry = Slots[Index];
                if (Entry.Completed.exchange(true)) return;
                auto Cancellation = Net::get_associated_cancellation_slot(Entry.Handler);
                if (Cancellation.is_connected()) Cancellation.clear();
                Completion Handler(CompletionDelivery(shared_from_this(), Index, std::move(Entry.Handler)));
                Detail::PostResult(Reclaimer->Executor(), std::move(Handler), Result);
            }
            auto CancelSlot(std::size_t Index, std::uint64_t Ticket) -> void
            {
                auto& Entry = Slots[Index];
                if (!Entry.Used.load() || Entry.Ticket.load() != Ticket || Entry.Completed.load()) return;
                Entry.Canceled = true;
                if (Active && *Active == Index) Entry.Cancel.emit(Net::cancellation_type::all);
                Notify();
            }
            [[nodiscard]] auto RequestCancel() -> ControlResult
            {
                Sealed.store(true);
                if (!Barrier.Enter())
                { if (Blocked.load()) return std::unexpected(RetainedFailure.Load()); return std::unexpected(Fault::Failure{Fault::Code::Canceled}); }
                return PostWake(WakeKind::StopCancel);
            }
            [[nodiscard]] auto RequestClose() -> ControlResult
            {
                Sealed.store(true);
                if (Closing.exchange(true)) { if (Blocked.load()) return std::unexpected(RetainedFailure.Load()); return {}; }
                if (!Barrier.Enter()) { Fail(); return std::unexpected(RetainedFailure.Load()); }
                CloseEntered.store(true);
                return PostWake(WakeKind::StopClose);
            }
            auto RequestRetirement() -> void override
            { if (!Closing.load()) { (void)RequestClose(); return; } if (!CloseIssued) (void)PostWake(WakeKind::StopClose); }
            auto Seal() noexcept -> void override { Sealed.store(true); Barrier.Seal(); }
            [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Reclaimer->Executor(); }
            [[nodiscard]] auto Drain() -> Net::awaitable<ControlResult> override
            { Seal(); return DrainState(shared_from_this()); }
            [[nodiscard]] static auto DrainState(std::shared_ptr<State> Owner) -> Net::awaitable<ControlResult>
            {
                co_await Net::this_coro::throw_if_cancelled(false);
                auto Result = co_await Owner->Barrier.Drain();
                if (Result) Result = co_await Owner->Tasks.Drain();
                if (!Result)
                {
                    if (Owner->Blocked.load(std::memory_order_acquire)) co_return std::unexpected(Owner->RetainedFailure.Load());
                    co_return std::unexpected(Result.error());
                }
                co_return ControlResult{};
            }
            auto Stop() -> bool
            {
                if (Terminal.Succeeded()) Terminal = {Fault::Code::Canceled};
                if (Active) Slots[*Active].Cancel.emit(Net::cancellation_type::all);
                const auto Canceled = Driver->Cancel();
                if (!Canceled) { Fail(Canceled.error()); return false; }
                Notify(); return true;
            }
            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            { return CloseConfirmed.load() && Barrier.Active() == 0 && Tasks.Active() == 0 && !Blocked.load(); }
            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
            { return Blocked.load() && (RetainedFailure.Load().Code == Fault::Code::Blocked || !Reclaimer->CanDispatch()); }
        };
    public:
        /** @brief 冷构造且显式注入真实共享池；不创建全局池或在热路径扩容。 */
        Writer(std::shared_ptr<Memory::BytePool> Bytes, std::shared_ptr<WriteDriver> Driver)
            : State_(std::make_shared<State>(std::move(Bytes), std::move(Driver))) {}
        /** @brief 大输入借用到completion，已交付字节在错误时保留；每请求只占一个64KiB块。 */
        auto Write(std::span<const std::byte> Input, Completion Handler) -> void { State_->Submit(Input, std::move(Handler), false); }
        auto WriteShutdown(Completion Handler) -> void { State_->Submit({}, std::move(Handler), true); }
        /** @brief 封止并请求取消真实driver；实际active回调退出前不归还块或槽。 */
        [[nodiscard]] auto Close() -> ControlResult { State_->Storage->Retain(State_); return State_->RequestClose(); }
        [[nodiscard]] auto Cancel() -> ControlResult { return State_->RequestCancel(); }
        [[nodiscard]] auto Drain() -> Net::awaitable<ControlResult>
        { return State_->Drain(); }
        [[nodiscard]] auto Activity() const -> std::shared_ptr<Prism::Contract::CarrierActivity> { return State_; }
        /** @brief 原域排他冷移交使用真实预约计数，不能据此推断并发发起安全。 */
        [[nodiscard]] auto IsIdle() const noexcept -> bool
        { return State_->Barrier.Active() == 0 && State_->Tasks.Active() == 0 && !State_->Barrier.IsBlocked(); }
    private:
        std::shared_ptr<State> State_;
    };
    inline Writer::CloseCompletion::~CloseCompletion()
    {
        if (!Owner) return;
        if (!Returned) { Owner->Fail(); return; }
        if (!Owner->CloseReturned.try_send(boost::system::error_code{})) Owner->Fail();
    }
    inline auto Writer::CloseCompletion::get_executor() const noexcept -> executor_type { return Owner->Reclaimer->Executor(); }
    inline auto Writer::CloseCompletion::operator()(std::exception_ptr Error, ControlResult Result) -> void
    {
        Returned = true;
        if (Error) { Owner->Fail(); Owner->Fatal->Publish(std::move(Error)); return; }
        if (!Result) Owner->Fail(Result.error());
    }
    inline Writer::CloseRetirement::~CloseRetirement() { if (Owner && !Returned) Owner->Fail(); }
    inline auto Writer::CloseRetirement::operator()(boost::system::error_code Error) -> void
    {
        Returned = true;
        if (Error) { Owner->Fail(Fault::FromNative(static_cast<std::error_code>(Error))); return; }
        if (Owner->Blocked.load(std::memory_order_acquire)) return;
        Owner->CloseConfirmed.store(true, std::memory_order_release);
        if (Owner->CloseEntered.exchange(false)) Owner->Barrier.Leave();
        Owner->Storage->Collect();
    }
    inline Writer::Release::~Release() { if (Owner && !Returned) Owner->Fail(); }
    inline auto Writer::Release::operator()(boost::system::error_code Error) -> void
    {
        if (Error) { Owner->Fail(Fault::FromNative(static_cast<std::error_code>(Error))); Returned = true; return; }
        auto& Entry = Owner->Slots[Index];
        if (Entry.NativeActive.load())
        { Owner->Fail(); Returned = true; return; }
        Entry.Chunk.reset(); Entry.Input = {}; Entry.Handler = nullptr;
        Entry.Ready.store(false);
        if (Entry.Entered) { Entry.Entered = false; Owner->Barrier.Leave(); }
        Entry.Used.store(false, std::memory_order_release); Returned = true;
        Owner->Storage->Collect();
    }
    inline Writer::CompletionDelivery::~CompletionDelivery()
    {
        if (!Owner_) return;
        if (!Returned_) { Owner_->Slots[Index_].Handler = std::move(Handler_); Owner_->Fail(); return; }
        if (!Owner_->Slots[Index_].Returned->try_send(boost::system::error_code{})) Owner_->Fail();
    }
    inline Writer::Wake::~Wake()
    { if (!Owner) return; if (!Returned) { Owner->Fail(); return; }
      if (Kind == WakeKind::StopCancel) Owner->Barrier.Leave(); Owner->Tasks.Leave(); Owner->Storage->Collect(); }
    inline auto Writer::Wake::operator()() -> void
    { if (Kind != WakeKind::Pump) Returned = Owner->Stop(); else { Owner->Pump(); Returned = true; } }
    inline auto Writer::CancelRequest::operator()(Net::cancellation_type Type) const -> void
    {
        if (Type == Net::cancellation_type::none) return;
        if (auto Value = Owner.lock())
        {
            if (!Value->Tasks.Enter()) return;
            const auto Result = Value->Reclaimer->Post(CancelAction(Value, Index, Ticket));
            if (!Result) Value->Fail(Result.error());
        }
    }
    inline Writer::CancelAction::~CancelAction()
    { if (!Owner) return; if (!Returned) { Owner->Fail(); return; } Owner->Tasks.Leave(); Owner->Storage->Collect(); }
    inline auto Writer::CancelAction::operator()() -> void
    { Owner->CancelSlot(Index, Ticket); Returned = true; }
    inline Writer::PartialCompletion::PartialCompletion(std::shared_ptr<State> Owner, std::size_t Index)
        : Owner_(std::move(Owner)), Index_(Index) {}
    inline Writer::PartialCompletion::~PartialCompletion()
    { if (!Owner_) return; Owner_->Slots[Index_].NativeActive.store(false); if (!Returned_) Owner_->Fail(); }
    inline auto Writer::PartialCompletion::get_executor() const noexcept -> executor_type { return Owner_->Reclaimer->Executor(); }
    /** @brief 归还路径晚于用户 handler 时只使用 State 的清理材料，不保存已消费的 erased 代理。 */
    inline auto Writer::PartialCompletion::get_allocator() const noexcept -> allocator_type
    { return Owner_->CleanupMemory; }
    inline auto Writer::PartialCompletion::get_cancellation_slot() const noexcept -> cancellation_slot_type { return Owner_->Slots[Index_].Cancel.slot(); }
    inline auto Writer::PartialCompletion::operator()(IoResult Result) -> void { Owner_->Partial(Index_, Result); Returned_ = true; }
}
