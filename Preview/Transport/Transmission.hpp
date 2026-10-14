/** @file Transmission.hpp @brief 唯一 typed I/O 前门、真实操作预约和原 executor 控制交付。 */
#pragma once
#include <tuple>
#include <Preview/Transport/Detail/TrackedCompletion.hpp>
#include <Preview/Transport/Detail/TransmissionControl.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_allocator.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <chrono>
#include <concepts>
#include <span>
#include <variant>
#include <optional>
namespace Preview
{
    namespace Net = boost::asio;
    /**
     * @brief 每次原生操作只经 StartRead/StartWrite 启动，callback 与 coroutine 共用同一预约。
     * @details Buffer 借用至 completion 返回；调用方串行发起每个方向。完成可在用户关联
     * executor，实物销毁和控制命令固定原 executor。取消不抹掉已完成字节；Close 只表示交付。
     * 输入所有权：ReadSome/WriteSome/ReadExact/WriteExact/WriteShutdown 的 span 只借用到该
     * 操作 completion，载体不复制也不延长其生命周期；Completion 按值转移给 TrackedCompletion，
     * 用户 handler 真正返回后归还操作预约，handler 被丢弃时其帧留在预建槽并记为 Blocked。
     * 恰一次且异步：结果统一经 Detail::PostResult 投递到 handler 关联 executor，绝不在发起点
     * 同步回调；exact 组合只在同一外层预约内逐步消费，零进度明确 WouldBlock、越界 InvalidArgument。
     * 输出与错误：唯一事实是 IoResult{Bytes, Failure}（token 形式）或 awaitable<IoResult>；
     * Close()/Cancel() 返回 ControlResult = expected<void, Fault::Failure>。远端 EOF 映射为
     * Fault::Code::Eof、取消为 Canceled、底层错误保留 Native 原 category/value，三类互不折叠。
     * 取消：Cancel() 可重复，每个命令占一条控制预约并投递回原 executor；已在排队前发生的取消
     * 直接交付 {0, Canceled}，已下发的原生操作仍由派生 OnCancel（如 socket cancel）完成后交付一次。
     * 半关闭：WriteShutdown 使用与 64 个数据槽分离的第 65 控制预约，成功只表示本端写方向已半关，
     * 读取方向保持可用；WriteShutdown 之后调用者仍须自行停止后续写。
     * 最终关闭者：Close() 封止新准入并交付派生 OnClose；只有 OwnsClose() 为真的层才行使底层
     * 最终关闭权，借用层（Replay 候选）Close 成功不等于底层已关闭，实际退出须等待 Activity()->Drain()。
     * 已接受下层关闭请求的包装层可要求外部真实 close/drain 回执；该回执到达前保留本层 Close 控制预约。
     * executor：冷构造固定的 Activity executor 是唯一状态域，控制命令在其上另建 strand 串行化；
     * 派生 Start* 与 OnClose/OnCancel 一律在该域执行，要求单一执行域，跨线程并发发起未受保护。
     * @note 未定义：Fault::Code 中没有与「LocalClosed」对应的独立类别（Foundation/Fault/Code.hpp
     * 未列出该码），本层只用 ControlOwner 的 LocalClosed 标志表达本层关闭命令已真实交付，
     * 调用方无法从 completion 区分「本层已关闭」与「底层已关闭」；该项留待 M13 之后统一决定。
     */
    class Transmission : public std::enable_shared_from_this<Transmission>
    {
    public:
        using ExecutorType = Net::any_io_executor;
        using executor_type = ExecutorType;
        using Completion = Transport::Detail::IoCompletion;
        using ControlResult = std::expected<void, Preview::Fault::Failure>;
        enum class Type : std::uint8_t { Tcp, Udp };
        explicit Transmission(ExecutorType Executor)
            : Activity_(std::make_shared<Transport::Detail::IoActivity>(Executor)),
              Control_(std::make_shared<ControlOwner>(std::move(Executor), Activity_)) {}
        Transmission(const Transmission&) = delete;
        auto operator=(const Transmission&) -> Transmission& = delete;
        Transmission(Transmission&&) = default;
        virtual ~Transmission() noexcept = default;
        [[nodiscard]] virtual auto Executor() const -> ExecutorType { return Activity_->Executor(); }
        [[nodiscard]] auto get_executor() const -> ExecutorType { return Executor(); }
        [[nodiscard]] virtual auto Activity() const noexcept -> std::shared_ptr<Contract::CarrierActivity> { return Activity_; }
        [[nodiscard]] virtual auto TransportType() const noexcept -> Type
        { if (const auto* Next = NextLayer()) return Next->TransportType(); return Type::Tcp; }

        /** @brief completion token 前门；全部关联属性在类型擦除前绑定并传入实际操作。 */
        template<class Token>
        auto ReadSome(std::span<std::byte> Buffer, Token&& Handler)
        { return Initiate(ReadRequest{Buffer, false}, std::forward<Token>(Handler)); }
        template<class Token>
        auto WriteSome(std::span<const std::byte> Buffer, Token&& Handler)
        { return Initiate(WriteRequest{Buffer, false}, std::forward<Token>(Handler)); }
        template<class Token>
        auto ReadExact(std::span<std::byte> Buffer, Token&& Handler)
        { return Initiate(ReadRequest{Buffer, true}, std::forward<Token>(Handler)); }
        template<class Token>
        auto WriteExact(std::span<const std::byte> Buffer, Token&& Handler)
        { return Initiate(WriteRequest{Buffer, true}, std::forward<Token>(Handler)); }
        [[nodiscard]] auto ReadSome(std::span<std::byte> Buffer) -> Net::awaitable<IoResult>;
        [[nodiscard]] auto WriteSome(std::span<const std::byte> Buffer) -> Net::awaitable<IoResult>;
        [[nodiscard]] auto ReadExact(std::span<std::byte> Buffer) -> Net::awaitable<IoResult>;
        [[nodiscard]] auto WriteExact(std::span<const std::byte> Buffer) -> Net::awaitable<IoResult>;
        /** @brief 真正半关闭在序列化write owner之后完成；反向读仍然可用。 */
        template<class Token>
        auto WriteShutdown(Token&& Handler) { return Initiate(ShutdownRequest{}, std::forward<Token>(Handler)); }
        [[nodiscard]] auto WriteShutdown() -> Net::awaitable<ControlResult>;
        /** @brief 封止新操作并交付实际关闭；成功只证明已接管命令，Drain另行等待实际退出。 */
        [[nodiscard]] auto Close() -> ControlResult
        { auto Result = Control_->Submit(weak_from_this().lock(), ControlOwner::CloseFlag);
          if (Result && OwnsClose()) Activity_->Seal(); return Result; }
        /** @brief 可重复取消；每次命令保持载体至原executor执行，拒绝/丢弃保留实物。 */
        [[nodiscard]] auto Cancel() -> ControlResult
        { return Control_->Submit(weak_from_this().lock(), ControlOwner::CancelFlag); }
        virtual auto SetTimeout(std::chrono::milliseconds Timeout) -> void
        { if (auto* Next = NextLayer()) Next->SetTimeout(Timeout); }
        [[nodiscard]] virtual auto IsOpen() const -> bool
        { if (const auto* Next = NextLayer()) return Next->IsOpen(); return false; }
        [[nodiscard]] virtual auto NextLayer() noexcept -> Transmission* { return nullptr; }
        [[nodiscard]] virtual auto NextLayer() const noexcept -> const Transmission* { return nullptr; }
        [[nodiscard]] virtual auto Release() -> std::shared_ptr<Transmission> { return {}; }
        template<class T>
        [[nodiscard]] auto lowest_layer() noexcept -> T*
        { auto* Current = this; while (auto* Next = Current->NextLayer()) Current = Next; return dynamic_cast<T*>(Current); }
        template<class T>
        [[nodiscard]] auto lowest_layer() const noexcept -> const T*
        { const auto* Current = this; while (const auto* Next = Current->NextLayer()) Current = Next; return dynamic_cast<const T*>(Current); }
    protected:
        /** @brief 原域排他冷移交前检查真实操作及控制预约；调用方同时停止所有发起者。 */
        [[nodiscard]] auto IoIdle() const noexcept -> bool { return Activity_->IsIdle(); }
        /** @brief 派生载体的握手/数据报等实际操作沿同一预约启动；Work只接受一次Completion。 */
        template<class Work>
        auto StartOwned(Work Operation, Completion Handler) -> void
        {
            auto Self = weak_from_this().lock();
            if (!Self) { Transport::Detail::PostResult(Activity_->Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            auto Reservation = Activity_->TryAcquire(Self);
            if (!Reservation) { Transport::Detail::PostResult(Activity_->Executor(), std::move(Handler), {0, Reservation.error()}); return; }
            Completion Tracked(Transport::Detail::TrackedCompletion(std::move(*Reservation), std::move(Handler)));
            const auto Allocator = Net::get_associated_allocator(Tracked);
            Net::post(Activity_->Executor(), Net::bind_allocator(Allocator,
                Auxiliary<Work>(Activity_->Executor(), std::move(Operation), Ready(std::move(Tracked)))));
        }
        /** @brief 已在原executor且持真实预约；派生owner必须只完成一次并完整透传关联属性。 */
        /** @brief 候选借用层可拒绝取得底层最终关闭权；其Close只交付候选局部动作。 */
        [[nodiscard]] virtual auto OwnsClose() const noexcept -> bool { return true; }
        /** @brief 真实下层 close/drain 才能完成的装饰层覆盖此能力。 */
        [[nodiscard]] virtual auto RequiresExternalCloseReceipt() const noexcept -> bool { return false; }
        /** @brief 冷构造时转移独立关闭回执 owner；不反向拥有 wrapper 或协议绑定。 */
        [[nodiscard]] auto CloseReceipt() const noexcept
            -> std::shared_ptr<Contract::CarrierCloseReceipt>
        { return Control_; }
        virtual auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void = 0;
        virtual auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void = 0;
        virtual auto StartWriteShutdown(Completion Handler) -> void = 0;
        [[nodiscard]] virtual auto OnClose() -> ControlResult = 0;
        [[nodiscard]] virtual auto OnCancel() -> ControlResult = 0;
    private:
        friend class Transport::Detail::TransmissionControlOwner;
        struct ReadyCompletion final { Completion Handler; Net::cancellation_state Cancellation; };
        template<class Work>
        struct Auxiliary final : Transport::Detail::AssociatedCompletion<Completion>
        {
            using executor_type = ExecutorType;
            ExecutorType Domain;
            Work Operation;
            Net::cancellation_state Cancellation;
            Auxiliary(ExecutorType Executor, Work Value, ReadyCompletion Ready)
                : Transport::Detail::AssociatedCompletion<Completion>(std::move(Ready.Handler)), Domain(std::move(Executor)),
                  Operation(std::move(Value)), Cancellation(Ready.Cancellation) {}
            [[nodiscard]] auto get_executor() const noexcept -> executor_type { return Domain; }
            auto operator()() -> void
            { if (!!Cancellation.cancelled()) { Transport::Detail::PostResult(Domain, std::move(this->Handler_), {0, {Fault::Code::Canceled}}); return; }
              Operation(std::move(this->Handler_)); }
        };
        struct ReadRequest final { std::span<std::byte> Buffer; bool Exact; };
        struct WriteRequest final { std::span<const std::byte> Buffer; bool Exact; };
        struct ShutdownRequest final {};
        // 私有传输操作类型必须与派生协议类可见的 Request 名称区分。
        using IoRequest = std::variant<ReadRequest, WriteRequest, ShutdownRequest>;
        struct ReadInput final { std::shared_ptr<Transmission> Carrier; std::span<std::byte> Buffer; };
        struct WriteInput final { std::shared_ptr<Transmission> Carrier; std::span<const std::byte> Buffer; };
        struct ExactRead final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Transport::Detail::ConfigureIo(Operation);
                IoResult Result;
                while (Result.Bytes < Input.Buffer.size())
                {
                    auto Part = co_await Input.Carrier->Step(ReadRequest{Input.Buffer.subspan(Result.Bytes), false}, Net::deferred);
                    if (Part.Bytes > Input.Buffer.size() - Result.Bytes)
                    { Result.Failure = {Fault::Code::InvalidArgument, Part.Failure.Native}; co_return std::tuple{Result}; }
                    Result.Bytes += Part.Bytes;
                    Result.Failure = Part.Failure;
                    if (Result.Failure.Failed()) co_return std::tuple{Result};
                    if (Part.Bytes == 0) { Result.Failure = {Fault::Code::WouldBlock}; co_return std::tuple{Result}; }
                }
                co_return std::tuple{Result};
            }
        };
        struct ExactWrite final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Transport::Detail::ConfigureIo(Operation);
                IoResult Result;
                while (Result.Bytes < Input.Buffer.size())
                {
                    auto Part = co_await Input.Carrier->Step(WriteRequest{Input.Buffer.subspan(Result.Bytes), false}, Net::deferred);
                    if (Part.Bytes > Input.Buffer.size() - Result.Bytes)
                    { Result.Failure = {Fault::Code::InvalidArgument, Part.Failure.Native}; co_return std::tuple{Result}; }
                    Result.Bytes += Part.Bytes;
                    Result.Failure = Part.Failure;
                    if (Result.Failure.Failed()) co_return std::tuple{Result};
                    if (Part.Bytes == 0) { Result.Failure = {Fault::Code::WouldBlock}; co_return std::tuple{Result}; }
                }
                co_return std::tuple{Result};
            }
        };
        struct Invocation final : Transport::Detail::AssociatedCompletion<Completion>
        {
            using executor_type = ExecutorType;
            std::shared_ptr<Transmission> Carrier;
            IoRequest Input;
            Net::cancellation_state Cancellation;
            Invocation(std::shared_ptr<Transmission> Owner, IoRequest Value, ReadyCompletion Ready)
                : AssociatedCompletion(std::move(Ready.Handler)), Carrier(std::move(Owner)), Input(Value), Cancellation(Ready.Cancellation) {}
            [[nodiscard]] auto get_executor() const noexcept -> executor_type { return Carrier->Activity_->Executor(); }
            auto operator()() -> void
            { if (!!Cancellation.cancelled()) { Transport::Detail::PostResult(Carrier->Activity_->Executor(), std::move(Handler_), {0, {Fault::Code::Canceled}}); return; }
              Carrier->Execute(Input, std::move(Handler_)); }
        };
        struct Initiation final
        {
            std::shared_ptr<Transmission> Carrier;
            IoRequest Input;
            ExecutorType Fallback;
            bool IsStep{false};
            template<class Handler>
            auto operator()(Handler&& Callback) -> void
            {
                const auto Executor = Net::get_associated_executor(Callback, Fallback);
                Completion Bound(Net::bind_executor(Executor, std::forward<Handler>(Callback)));
                if (!Carrier) { Transport::Detail::PostResult(Fallback, std::move(Bound), {0, {Fault::Code::InvalidArgument}}); return; }
                if (IsStep) Carrier->BeginStep(Input, std::move(Bound));
                else Carrier->Begin(Input, std::move(Bound));
            }
        };
        [[nodiscard]] static auto Ready(Completion Handler) -> ReadyCompletion
        {
            Transport::Detail::QueuedCompletion Queued(std::move(Handler));
            const auto Cancellation = Queued.Cancellation();
            return {Completion(std::move(Queued)), Cancellation};
        }
        [[nodiscard]] static auto AwaitOperation(Initiation Value) -> Net::awaitable<IoResult>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            const auto Cancellation = co_await Net::this_coro::cancellation_state;
            if (!!Cancellation.cancelled())
            {
                co_await Net::post(Value.Fallback, Net::use_awaitable);
                co_return IoResult{0, {Fault::Code::Canceled}};
            }
            auto Token = Net::use_awaitable;
            co_return co_await Net::async_initiate<Net::use_awaitable_t<>, void(IoResult)>(std::move(Value), Token);
        }
        [[nodiscard]] static auto AwaitShutdown(Initiation Value) -> Net::awaitable<ControlResult>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            const auto Result = co_await AwaitOperation(std::move(Value));
            if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
            co_return ControlResult{};
        }
        template<class Token>
        auto Initiate(IoRequest Input, Token&& Handler)
        {
            return Net::async_initiate<Token, void(IoResult)>(
                Initiation{weak_from_this().lock(), Input, Activity_->Executor(), false}, Handler);
        }
        template<class Token>
        auto Step(IoRequest Input, Token&& Handler)
        {
            return Net::async_initiate<Token, void(IoResult)>(
                Initiation{weak_from_this().lock(), Input, Activity_->Executor(), true}, Handler);
        }
        auto BeginStep(IoRequest Input, Completion Handler) -> void
        {
            const auto Allocator = Net::get_associated_allocator(Handler);
            Net::post(Activity_->Executor(), Net::bind_allocator(Allocator,
                Invocation(weak_from_this().lock(), Input, Ready(std::move(Handler)))));
        }
        auto Begin(IoRequest Input, Completion Handler) -> void
        {
            auto Self = weak_from_this().lock();
            if (!Self) { Transport::Detail::PostResult(Activity_->Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            auto Reservation = Reserve(Input, Self);
            if (!Reservation) { Transport::Detail::PostResult(Activity_->Executor(), std::move(Handler), {0, Reservation.error()}); return; }
            Completion Tracked(Transport::Detail::TrackedCompletion(std::move(*Reservation), std::move(Handler)));
            const auto Allocator = Net::get_associated_allocator(Tracked);
            Net::post(Activity_->Executor(), Net::bind_allocator(Allocator,
                Invocation(std::move(Self), Input, Ready(std::move(Tracked)))));
        }
        /** @brief 写半关闭使用独立控制预约，64个数据操作不占用其准入额度。 */
        [[nodiscard]] auto Reserve(const IoRequest& Input, std::shared_ptr<Transmission> Carrier)
            -> std::expected<Transport::Detail::IoActivity::Operation, Fault::Failure>
        {
            if (std::holds_alternative<ShutdownRequest>(Input)) return Activity_->TryAcquireControl(std::move(Carrier));
            return Activity_->TryAcquire(std::move(Carrier));
        }
        auto Execute(IoRequest Input, Completion Handler) -> void
        {
            if (auto* Read = std::get_if<ReadRequest>(&Input))
            {
                if (!Read->Exact) { StartRead(Read->Buffer, std::move(Handler)); return; }
                Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(ExactRead{}, Executor()),
                    Handler, ReadInput{weak_from_this().lock(), Read->Buffer});
                return;
            }
            if (auto* Write = std::get_if<WriteRequest>(&Input))
            {
                if (!Write->Exact) { StartWrite(Write->Buffer, std::move(Handler)); return; }
                Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(ExactWrite{}, Executor()),
                    Handler, WriteInput{weak_from_this().lock(), Write->Buffer});
                return;
            }
            StartWriteShutdown(std::move(Handler));
        }
        using ControlOwner = Preview::Transport::Detail::TransmissionControlOwner;
        std::shared_ptr<Transport::Detail::IoActivity> Activity_;
        std::shared_ptr<ControlOwner> Control_;
    };
    inline auto Transport::Detail::TransmissionControlOwner::Delivery::operator()() -> void
    {
        Invoked = true;
        try
        {
            Succeeded = Owner->Execute(Index, HandlerInvoked);
            Returned = true;
        }
        catch (...)
        {
            if (HandlerInvoked)
                Owner->RecordKnownFailure(Index, {Fault::Code::Blocked});
            else
                Owner->FailUnknown();
            throw;
        }
    }

    inline auto Transport::Detail::TransmissionControlOwner::Submit(
        std::shared_ptr<Transmission> Carrier,
        unsigned Flag) -> ControlResult
    {
        if (!Carrier)
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        if (Flag == CancelFlag)
        {
            const auto CloseWasAccepted = AcceptedClose.load(std::memory_order_acquire);
            const auto WasClosedLocally = LocalClosed.load(std::memory_order_acquire);
            const auto WasFinished = Finished.load(std::memory_order_acquire);
            if (WasClosedLocally || WasFinished) return {};
            if (Blocked.load(std::memory_order_acquire))
                return std::unexpected(Failure.Load());
            const auto ExistingFailure = Failure.Load();
            if (ExistingFailure.Failed()) return std::unexpected(ExistingFailure);
            if (CloseWasAccepted) return {};
        }
        else if (Finished.load(std::memory_order_acquire) ||
                 (Flag == CloseFlag && LocalClosed.load(std::memory_order_acquire)))
        {
            return {};
        }

        std::size_t Index = CancelCapacity;
        if (Flag == CloseFlag)
        {
            if (Commands[Index].Used.exchange(true))
            {
                if (Blocked.load(std::memory_order_acquire))
                    return std::unexpected(Failure.Load());
                return {};
            }
        }
        else
        {
            for (Index = 0; Index < CancelCapacity; ++Index)
                if (!Commands[Index].Used.exchange(true)) break;
            if (Index == CancelCapacity)
                return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable});
        }

        auto Reservation = Activity->TryAcquireControl(Carrier);
        if (!Reservation)
        {
            Commands[Index].Used.store(false);
            return std::unexpected(Reservation.error());
        }
        Commands[Index].Reservation.emplace(std::move(*Reservation));
        Commands[Index].Carrier.store(std::move(Carrier));
        Commands[Index].Retryable.store(false);
        Commands[Index].RetryInFlight.store(false);
        Commands[Index].KnownControlFailure.store(false);
        Commands[Index].AwaitingExternalReceipt.store(false);

        // 原执行域停止是尚未交付的已知拒绝；保留同一命令和真实预约供显式重试。
        if (!Reclaimer->CanDispatch() && !Reclaimer->IsQuarantined())
        {
            const Fault::Failure Deferred{Fault::Code::Blocked};
            RecordKnownFailure(Index, Deferred);
            Commands[Index].Retryable.store(true, std::memory_order_release);
            return std::unexpected(Deferred);
        }
        const auto Posted = Reclaimer->Post(Delivery(shared_from_this(), Index));
        if (!Posted)
        {
            FailUnknown(Posted.error());
        }
        else if (Flag == CloseFlag)
        {
            AcceptedClose.store(true, std::memory_order_release);
        }
        return Posted;
    }

    inline auto Transport::Detail::TransmissionControlOwner::Execute(
        std::size_t Index,
        bool& HandlerInvoked) -> bool
    {
        const auto Carrier = Commands[Index].Carrier.load();
        if (!Carrier)
        {
            FailUnknown();
            return false;
        }
        if (ExternalCloseConfirmed.load(std::memory_order_acquire))
        {
            HandlerInvoked = true;
            return true;
        }
        // 外部物理关闭回执可能先于本次 RequestClose 的历史失败结果到达。
        if (Index == CancelCapacity && Carrier->RequiresExternalCloseReceipt())
            Commands[Index].AwaitingExternalReceipt.store(true, std::memory_order_release);
        HandlerInvoked = true;
        const auto Result = Index == CancelCapacity ? Carrier->OnClose() : Carrier->OnCancel();
        if (!Result)
        {
            RecordKnownFailure(Index, Result.error());
            return false;
        }
        if (Index == CancelCapacity)
        {
            if (Carrier->RequiresExternalCloseReceipt())
            {
                Commands[Index].AwaitingExternalReceipt.store(true, std::memory_order_release);
                Storage->Retain(shared_from_this());
                return true;
            }
            Activity->RecordCloseDelivered();
            LocalClosed.store(true, std::memory_order_release);
            if (Carrier->OwnsClose()) Finished.store(true);
        }
        return true;
    }

    inline auto Transmission::ReadSome(std::span<std::byte> Buffer) -> Net::awaitable<IoResult>
    { return AwaitOperation(Initiation{weak_from_this().lock(), ReadRequest{Buffer, false}, Activity_->Executor(), false}); }
    inline auto Transmission::WriteSome(std::span<const std::byte> Buffer) -> Net::awaitable<IoResult>
    { return AwaitOperation(Initiation{weak_from_this().lock(), WriteRequest{Buffer, false}, Activity_->Executor(), false}); }
    inline auto Transmission::ReadExact(std::span<std::byte> Buffer) -> Net::awaitable<IoResult>
    { return AwaitOperation(Initiation{weak_from_this().lock(), ReadRequest{Buffer, true}, Activity_->Executor(), false}); }
    inline auto Transmission::WriteExact(std::span<const std::byte> Buffer) -> Net::awaitable<IoResult>
    { return AwaitOperation(Initiation{weak_from_this().lock(), WriteRequest{Buffer, true}, Activity_->Executor(), false}); }
    inline auto Transmission::WriteShutdown() -> Net::awaitable<ControlResult>
    { return AwaitShutdown(Initiation{weak_from_this().lock(), ShutdownRequest{}, Activity_->Executor(), false}); }
    using SharedTransmission = std::shared_ptr<Transmission>;
    template<class T>
    concept TransmissionLike = requires(T& Value, std::span<std::byte> Read, std::span<const std::byte> Write)
    {
        { Value.ReadSome(Read) } -> std::same_as<Net::awaitable<IoResult>>;
        { Value.WriteSome(Write) } -> std::same_as<Net::awaitable<IoResult>>;
        { Value.Close() } -> std::same_as<Transmission::ControlResult>;
        { Value.Cancel() } -> std::same_as<Transmission::ControlResult>;
        { Value.WriteShutdown() } -> std::same_as<Net::awaitable<Transmission::ControlResult>>;
    };
    static_assert(TransmissionLike<Transmission>);
}
