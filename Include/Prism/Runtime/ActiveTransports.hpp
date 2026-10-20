/** @file ActiveTransports.hpp @brief 载体观察 pin、真实完成源与原 executor 退休。 */
#pragma once
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Contract/Ingress/DatagramSession.hpp>
#include <Prism/Contract/Ingress/MuxSession.hpp>
#include <Prism/Runtime/CarrierDomain.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <utility>
namespace Prism::Runtime
{
    struct ActiveTransportSnapshot final
    {
        Prism::SharedTransmission Inbound, Outbound;
        std::shared_ptr<Prism::Contract::DatagramSession> Datagram;
        std::shared_ptr<Prism::Contract::MuxSession> Mux;
    };
    /** @brief 每个物理 Identity/Domain 只登记一个 owner；各类型槽只选择可加载的 view。
     * @details Store/Clear 槽切换不封止共享 CarrierActivity；Finalize 才关闭并排空唯一 owner。
     * 生产方必须把返回的别名 owner 放进实际协程/handler，不能另外留下未计数 native owner。
     */
    class ActiveTransports final
    {
        using Failure = Prism::Fault::Failure;
        enum class Kind { Inbound, Outbound, Datagram, Mux };
        enum class OwnerKind { Stream, Datagram, Mux };
        [[nodiscard]] static auto OwnerKindOf(const ActiveTransportSnapshot& Value) noexcept
            -> OwnerKind;
        struct Resource final : Prism::Executor::ClosingResource, std::enable_shared_from_this<Resource>
        {
            Resource(CarrierDomain Domain, ActiveTransportSnapshot Value);
            /** @brief 别名控制块的唯一预约；shared view 的副本共享它，最后一份退出才 Leave。 */
            struct ViewPin final
            {
                std::shared_ptr<Resource> Owner;
                Prism::Lifecycle::DrainReservation Reservation;
                ViewPin(std::shared_ptr<Resource> Resource, Prism::Lifecycle::DrainReservation Lease)
                    : Owner(std::move(Resource)), Reservation(std::move(Lease))
                {
                }
            };
            struct Delivery final
            {
                std::shared_ptr<Resource> Owner;
                bool Invoked{false};
                explicit Delivery(std::shared_ptr<Resource> Value);
                Delivery(Delivery&& Other) noexcept;
                ~Delivery();
                auto operator()() -> void;
            };
            struct RetirementCompletion final
            {
                std::shared_ptr<Resource> Owner;
                bool Invoked{false};
                explicit RetirementCompletion(std::shared_ptr<Resource> Value);
                RetirementCompletion(RetirementCompletion&& Other) noexcept;
                ~RetirementCompletion();
                auto operator()(std::exception_ptr Fatal) -> void;
            };
        private:
            friend class ActiveTransports;
            /** @brief 在读取 carrier 字段前即成立 view 预约，避免 Seal/clear 并发空窗。 */
            template<class Carrier>
            [[nodiscard]] auto View(Kind Type)
                -> std::expected<std::shared_ptr<Carrier>, Failure>;
        public:
            /** @brief 验证候选是否指向同一物理 Identity 与真实执行域。 */
            [[nodiscard]] auto Matches(const Resource& Other) const -> bool;
            /** @brief 拒绝已关闭、已退休或已有终态失败的 owner view。 */
            [[nodiscard]] auto CanAcceptView() const noexcept -> bool;
            auto RequestRetirement() -> void override;
            auto Fail(Failure Error, const bool DispatchUnavailable = false) noexcept -> void;
            [[nodiscard]] auto Error() const noexcept -> Failure;
            auto Close() -> void;
            /** @brief 保存由调用方明确提出的取消意图，最终控制仍在原 executor 执行。 */
            auto MarkCancelRequested() noexcept -> void;
            /** @brief 新输入被拒绝时必须取消既有操作；与仍供 outer 使用的旧 inner 释放不同。 */
            auto Reject() -> void;
            /** @brief 保留全部已借出的 view；这里只撤销准入，不声明 carrier 或 I/O 退休。 */
            auto Release() -> void;
            auto Execute() -> void;
            static auto Retire(std::shared_ptr<Resource> Self) -> Net::awaitable<void>;
            /** @brief 实际退休协程与完成通知都退出后，才归还唯一退休预约。 */
            auto FinishRetirement() noexcept -> void;
            auto CloseValue() -> std::expected<void, Failure>;
            auto CloseStream(
                const Prism::SharedTransmission& Stream,
                const bool CancelInFlight)
                -> std::expected<void, Failure>;
            [[nodiscard]] auto IsRetired() const noexcept -> bool override;
            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override;
            const Net::any_io_executor DomainExecutor;
            std::shared_ptr<Prism::Executor::ContextOwner> Context;
            std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
            std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
            std::shared_ptr<Prism::Contract::CarrierActivity> Activity;
            OwnerKind OwnerType;
            Prism::Lifecycle::DrainBarrier Views, Completion;
            std::optional<Prism::Lifecycle::DrainReservation> CompletionReservation;
            ActiveTransportSnapshot Value;
            const void* Identity{nullptr};
            std::atomic<bool> Queued{false}, Closing{false}, Releasing{false}, Retiring{false}, Retired{false};
            std::atomic<bool> Rejecting{false};
            std::atomic<bool> CancelRequested{false};
            std::atomic<bool> ExecutionProhibited{false}, ContentsReleased{false};
            std::atomic<bool> DispatchUnavailable{false};
            Prism::Fault::FailureState FailureState;
        };
    public:
        /** @brief 按值接管入站；成功返回唯一正式别名 owner，拒绝也保留原 executor 实物。
         * @details 调用者应移入 native owner 并在实际处理字段中采用返回值；Activity 必须由真实 I/O producer 提供。
         */
        [[nodiscard]] auto StoreInbound(Prism::SharedTransmission Value, const CarrierDomain& Domain)
            -> std::expected<Prism::SharedTransmission, Failure>;
        /** @brief 出站同入站所有权合同；不得把返回 owner 丢弃后继续使用未计数 native 副本。 */
        [[nodiscard]] auto StoreOutbound(Prism::SharedTransmission Value, const CarrierDomain& Domain)
            -> std::expected<Prism::SharedTransmission, Failure>;
        /** @brief 接管协议 Run owner；Domain 在移交前由实际协议 owner 固定，不借用 Session executor 猜测。 */
        [[nodiscard]] auto StoreDatagram(std::shared_ptr<Prism::Contract::DatagramSession> Value, const CarrierDomain& Domain)
            -> std::expected<std::shared_ptr<Prism::Contract::DatagramSession>, Failure>;
        /** @brief 接管 mux 根；真实 Run/子操作 completion 由 Activity 保证，拒绝保留整个根。 */
        [[nodiscard]] auto StoreMux(std::shared_ptr<Prism::Contract::MuxSession> Value, const CarrierDomain& Domain)
            -> std::expected<std::shared_ptr<Prism::Contract::MuxSession>, Failure>;
        /** @brief 移除指定类型的当前 view 选择；物理 owner 仍由唯一资源槽持有至 Finalize。 */
        [[nodiscard]] auto ClearInbound() -> std::expected<void, Failure>;
        [[nodiscard]] auto ClearOutbound() -> std::expected<void, Failure>;
        [[nodiscard]] auto ClearDatagram() -> std::expected<void, Failure>;
        [[nodiscard]] auto ClearMux() -> std::expected<void, Failure>;
        /** @brief 创建拥有 view 预约的别名 owner；空返回表示当前槽不存在或已封止。 */
        [[nodiscard]] auto LoadInbound() const -> Prism::SharedTransmission;
        [[nodiscard]] auto LoadOutbound() const -> Prism::SharedTransmission;
        /** @brief 快照的每个非空 shared 字段都独立 pin 原资源/context，须保活至实际 completion 退栈。 */
        [[nodiscard]] auto Load() const -> ActiveTransportSnapshot;
        /** @brief 封止新 view，按 mux、datagram、stream 的 owner 依赖顺序请求关闭。 */
        [[nodiscard]] auto RequestClose() -> std::expected<void, Failure>;
        /** @brief 封止新 owner 并保留显式取消意图，随后仍由预建 close action 投递关闭。 */
        auto MarkCancelRequested() noexcept -> void;
        /** @brief 按根 owner 到 stream owner 顺序逐层关闭并排空。
         * @details 调用方须先停止 Store producer 和 carrier 操作；真实 I/O 完成只从 Activity::Drain 得到。
         * mux/datagram 完成前不关闭下层 stream，以免取消先打断仍由根 owner 管理的操作。
         */
        [[nodiscard]] auto Finalize() -> Net::awaitable<std::expected<void, Failure>>;
    private:
        [[nodiscard]] auto HasOwner(OwnerKind Type) const -> bool;
        [[nodiscard]] auto RequestCloseOwners(OwnerKind Type) -> std::expected<void, Failure>;
        [[nodiscard]] auto FinalizeOwners(OwnerKind Type)
            -> Net::awaitable<std::expected<void, Failure>>;
        [[nodiscard]] auto Clear(Kind Type) -> std::expected<void, Failure>;
        template<class Carrier>
        [[nodiscard]] auto LoadView(Kind Type) const -> std::shared_ptr<Carrier>;
        /** @brief 取得输入物理载体提供的真实操作完成源。 */
        [[nodiscard]] static auto ActivityOf(const ActiveTransportSnapshot& Value)
            -> std::shared_ptr<Prism::Contract::CarrierActivity>;
        /** @brief 读取输入 carrier 自身执行域；协议根使用其真实 Activity executor。 */
        [[nodiscard]] static auto CarrierExecutorOf(
            const ActiveTransportSnapshot& Value,
            const std::shared_ptr<Prism::Contract::CarrierActivity>& Activity)
            -> Net::any_io_executor;
        /** @brief 在不能证明输入执行域时保留原 owner，但禁止调度或触碰 native carrier。 */
        static auto RetainRejectedInputOn(
            const CarrierDomain& Domain,
            ActiveTransportSnapshot Input,
            const Failure Error) -> void;
        /** @brief 优先在输入 owner 自己的 context 固定拒绝资源。 */
        static auto RetainRejectedInput(
            const CarrierDomain& Domain,
            ActiveTransportSnapshot Input,
            const Failure Error) -> void;
        [[nodiscard]] auto StoreStream(Kind Type, Prism::SharedTransmission Value, const CarrierDomain& Domain)
            -> std::expected<Prism::SharedTransmission, Failure>;
        template<class Carrier>
        [[nodiscard]] auto Store(Kind Type, ActiveTransportSnapshot Input, const CarrierDomain& Domain)
            -> std::expected<std::shared_ptr<Carrier>, Failure>;
        /** @brief 复用同 Identity/Domain 的 owner；新物理 owner 受固定槽预算约束。 */
        [[nodiscard]] auto ReserveResource(const std::shared_ptr<Resource>& Candidate,
                                           const CarrierDomain& Domain)
            -> std::expected<std::shared_ptr<Resource>, Failure>;
        std::atomic<bool> Closing_{false};
        /** @brief 64 个唯一物理 owner 的 admission budget；同 Identity/Domain 的 Store 复用原槽。 */
        std::array<std::atomic<std::shared_ptr<Resource>>, 64> Slots_;
        std::array<std::atomic<std::shared_ptr<Resource>>, 4> Current_;
    };
}
