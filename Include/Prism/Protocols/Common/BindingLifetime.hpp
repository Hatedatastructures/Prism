/** @file BindingLifetime.hpp @brief 协议绑定的实际退栈屏障、原 executor 退休及失败实物所有权。 */
#pragma once
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/strand.hpp>
#include <atomic>
#include <expected>
#include <exception>
#include <vector>
#include <chrono>
#include <cstddef>
#include <memory>
#include <span>
#include <tuple>
#include <utility>
namespace Prism::Protocols
{
    namespace Net = boost::asio;
    class BindingLifetime final
    {
        struct CloseState final
        {
            CloseState(Net::any_io_executor Executor, Prism::Foundation::GenerationPin Pin);
            Prism::Foundation::GenerationPin Generation;
            std::shared_ptr<Prism::Executor::ContextOwner> Context;
            std::weak_ptr<Prism::Executor::ClosingStorage> Storage;
            Prism::Lifecycle::DrainBarrier Barrier;
            Prism::Fault::FailureState Failure;
        };
    public:
        class Activity;
    private:
        struct ClosingSlot final : Prism::Executor::ClosingResource
        {
            auto RequestRetirement() noexcept -> void override;
            [[nodiscard]] auto IsRetired() const noexcept -> bool override { return !Failed.load(); }
            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override { return DispatchFailed.load(); }
            std::weak_ptr<Activity> Active;
            std::atomic<std::shared_ptr<Activity>> Failed;
            std::weak_ptr<Prism::Executor::ClosingStorage> Storage;
            std::atomic<bool> BindingOwned{true};
            std::atomic<bool> Activated{false}, PhysicallyRetired{false};
            std::atomic<bool> DispatchFailed{false}, RetryPending{false};
        };
    public:
        /** @brief 拥有载体、实际 executor context/allocator 和关闭状态；只 weak 联系预构造槽位。 */
        class Activity final : public std::enable_shared_from_this<Activity>
        {
        public:
            Activity(std::shared_ptr<CloseState> State, Prism::SharedTransmission Carrier);
            ~Activity();
            auto Attach(std::shared_ptr<ClosingSlot> Slot) -> void;
            /** @brief 冷接入独立传输控制回执；关闭期间不借用 wrapper 的生存期。 */
            auto AttachCloseReceipt(
                std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt) noexcept -> void;
            /** @brief 任意线程只提交关闭请求，载体检查/取消/最终释放均在原 executor。
             * @details 永久虚关闭失败由 typed Drain 报告；真正不可投递才隔离至 L1。
             */
            [[nodiscard]] auto RequestClose() noexcept
                -> Prism::Transmission::ControlResult;
            [[nodiscard]] auto Carrier() const noexcept -> Prism::SharedTransmission { return Carrier_.load(); }
            [[nodiscard]] auto Executor() const -> Net::any_io_executor { return Executor_; }
            /** @brief 关闭已请求或实物已退休后，拒绝新数据面 I/O。 */
            [[nodiscard]] auto IsCloseRequested() const noexcept -> bool
            { return CloseRequested_.load(std::memory_order_acquire) || Retired_.load(std::memory_order_acquire); }
            /** @brief 保留实际 I/O 计数；调用者必须在载体 executor 执行并在退栈时 EndIo。 */
            auto BeginIo() noexcept -> void { IoActive_.fetch_add(1); }
            auto EndIo() noexcept -> void;
            /** @brief L1 仅重试失败关闭 owner；普通 Close/析构保持唯一一次提交。 */
            auto RequestRetirement() noexcept -> void;
            /** @brief binding 最后释放时接管尚未执行的关闭请求，覆盖已投递后 executor 停止。 */
            auto ReleaseBinding() noexcept -> void;
        private:
            [[nodiscard]] auto DispatchClose(const std::shared_ptr<ClosingSlot>& Slot) noexcept
                -> Prism::Transmission::ControlResult;
            [[nodiscard]] auto CanDispatch() const noexcept -> bool { return !Context_ || Context_->CanDispatch(); }
            auto HoldFailure(
                Prism::Fault::Failure Reason,
                const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void;
            auto StartCloseOnExecutor(const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void;
            auto CompleteClose(
                std::exception_ptr Error,
                Prism::Transmission::ControlResult Result,
                const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void;
            [[nodiscard]] auto CloseAndDrain()
                -> Net::awaitable<Prism::Transmission::ControlResult>;
            auto PublishFatal(
                std::exception_ptr Error,
                const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void;
            auto FinishClose(const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void;
            auto ReleaseFailedSlot(const std::shared_ptr<ClosingSlot>& Slot) noexcept -> void;
            std::shared_ptr<CloseState> State_;
            std::atomic<Prism::SharedTransmission> Carrier_;
            Net::any_io_executor Executor_;
            std::shared_ptr<Prism::Executor::ContextOwner> Context_;
            Prism::Executor::ExecutorReclaimer Reclaimer_;
            std::weak_ptr<ClosingSlot> Slot_;
            std::atomic<std::size_t> IoActive_{0};
            std::atomic<std::shared_ptr<Prism::Contract::CarrierCloseReceipt>> CloseReceipt_;
            std::atomic<bool> CloseRequested_{false}, CloseInFlight_{false}, Retired_{false};
        };
        using SharedActivity = std::shared_ptr<Activity>;
        BindingLifetime(
            Net::any_io_executor Executor,
            Prism::Foundation::GenerationPin Generation);
        ~BindingLifetime() noexcept;
        /** @brief 接管载体与一次预约；预构造失败槽位，构造/登记异常由 RAII 精确退计数。 */
        [[nodiscard]] auto Enter(Prism::SharedTransmission Carrier) -> SharedActivity;
        /** @brief 封止接入并请求实际 owner 关闭；不访问载体状态。 */
        auto Close() noexcept -> void;
        [[nodiscard]] auto Closed() const noexcept -> bool { return Closed_.load(); }
        /** @brief 只观察已激活载体真实退休及全部 activity 退栈；业务首因仍由 Drain 返回。
         * @details 冷 Enter 后未完成 wrapper 构造的预约不转移载体关闭权；原 caller 仍拥有它。
         *          激活槽仅由底层和 wrapper Drain 成功且 IoActive 归零的 FinishClose 发布终态。
         */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;
        /** @brief 等待载体关闭控制、Activity completion 和 wrapper 退栈；失败保留真实 owner。 */
        auto Drain() -> Net::awaitable<std::expected<void,Prism::Fault::Failure>>;
    private:
        using Entries = std::vector<std::shared_ptr<ClosingSlot>>;
        std::shared_ptr<CloseState> State_;
        std::atomic<bool> Closed_{false};
        std::atomic<std::shared_ptr<const Entries>> Entries_{std::make_shared<const Entries>()};
    };
    /** @brief 真实传输 owner；异步调用保留 activity/carrier，结果沿正式前门恰好交付一次。 */
    class BoundTransmission final : public Prism::Transmission
    {
        struct IoReservation final
        {
            explicit IoReservation(BindingLifetime::SharedActivity Value);
            ~IoReservation();
            BindingLifetime::SharedActivity Activity;
        };
        struct ReadInput final { std::shared_ptr<BoundTransmission> Owner; std::span<std::byte> Buffer; };
        struct WriteInput final { std::shared_ptr<BoundTransmission> Owner; std::span<const std::byte> Buffer; };
        struct ShutdownInput final { std::shared_ptr<BoundTransmission> Owner; };
        /** @brief 载体已退休时的确定失败；保留协议私有 NotOpen 的原生 category/value。 */
        static auto NotOpen() -> Prism::IoResult;
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                IoReservation Io(Input.Owner->Activity_);
                if (Io.Activity->IsCloseRequested()) co_return std::tuple{NotOpen()};
                auto Carrier = Io.Activity->Carrier();
                if (!Carrier) co_return std::tuple{NotOpen()};
                co_return std::tuple{co_await Net::co_spawn(
                    Carrier->Executor(), Carrier->ReadSome(Input.Buffer), Net::deferred)};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                IoReservation Io(Input.Owner->Activity_);
                if (Io.Activity->IsCloseRequested()) co_return std::tuple{NotOpen()};
                auto Carrier = Io.Activity->Carrier();
                if (!Carrier) co_return std::tuple{NotOpen()};
                co_return std::tuple{co_await Net::co_spawn(
                    Carrier->Executor(), Carrier->WriteSome(Input.Buffer), Net::deferred)};
            }
        };
        struct ShutdownWork final
        {
            template<class State>
            auto operator()(State Operation, ShutdownInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                IoReservation Io(Input.Owner->Activity_);
                if (Io.Activity->IsCloseRequested()) co_return std::tuple{NotOpen()};
                auto Carrier = Io.Activity->Carrier();
                if (!Carrier) co_return std::tuple{NotOpen()};
                const auto Result = co_await Net::co_spawn(
                    Carrier->Executor(), Carrier->WriteShutdown(), Net::deferred);
                if (!Result) co_return std::tuple{Prism::IoResult{0, Result.error()}};
                co_return std::tuple{Prism::IoResult{0, {}}};
            }
        };
    public:
        explicit BoundTransmission(BindingLifetime::SharedActivity Activity);
        ~BoundTransmission() noexcept override;
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Activity_->Executor(); }
        /** @brief 部分读取；真实 I/O 预约保持到完成交付后才归还。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        { Initiate<ReadWork>(ReadInput{Owner(), Buffer}, std::move(Handler)); }
        /** @brief 部分写入；保留底层短写语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        { Initiate<WriteWork>(WriteInput{Owner(), Buffer}, std::move(Handler)); }
        /** @brief 真实写半关闭转交真实载体；反向读取仍然可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        { Initiate<ShutdownWork>(ShutdownInput{Owner()}, std::move(Handler)); }
        [[nodiscard]] auto RequiresExternalCloseReceipt() const noexcept -> bool override { return true; }
        [[nodiscard]] auto OnClose() -> ControlResult override;
        /** @brief 可重复取消真实载体的挂起操作；成功只表示命令已接管。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override;
        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override { if (auto Value = Activity_->Carrier()) Value->SetTimeout(Timeout); }
        [[nodiscard]] auto IsOpen() const -> bool override { auto Value = Activity_->Carrier(); return Value && Value->IsOpen(); }
        /** @brief 仅原 executor 的同步借用；不得跨 co_await 或与最终退休并发，退休后为 null。 */
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override { return Activity_->Carrier().get(); }
        /** @brief 仅原 executor 的同步借用；调用者保留外层 owner，禁止跨挂起和并发退休。 */
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission* override { return Activity_->Carrier().get(); }
    private:
        /** @brief 完成交付前的真实 owner 借用；存活由外层 shared_ptr 与本次预约共同保证。 */
        [[nodiscard]] auto Owner() -> std::shared_ptr<BoundTransmission>;
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }
        BindingLifetime::SharedActivity Activity_;
    };
}
