/**
 * @file InboundAdmission.hpp
 * @brief 预预约入站失败资源退休所有者与唯一数据面发布入口。
 */
#pragma once

#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Ingress/AdmissionTransportRetirement.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/awaitable.hpp>
#include <exception>
#include <expected>
#include <memory>

namespace Prism::Contract
{
    class AdmissionRetirementState;

    /**
     * @class InboundAdmission
     * @brief 在握手前预约并拥有一次入站退休能力。
     * @details 本票据保留 inbound、已登记载体、数据面及相关租约的共享 owner。成功 Admit
     *          时把数据面交回调用者，之后的关闭归对应协议/数据面 owner；拒绝或失败时本票据
     *          请求 Cancel/Close 并等待真实 drain。已预约票据的重试在 inbound 原 executor 执行；
     *          预约分配失败时委托传输预建的 ControlOwner/Activity。等待取消或失败不会释放未退休
     *          资源。本类不执行 stream 半关闭，物理关闭仍由 Transmission/协议关闭 owner 完成。
     */
    class InboundAdmission final
    {
        using RetirementState = AdmissionRetirementState;

    public:
        using Outcome = AcceptOutcome;
        using PrepareResult = std::expected<InboundAdmission, Prism::Fault::Failure>;

        InboundAdmission() = delete;
        InboundAdmission(const InboundAdmission&) = delete;
        auto operator=(const InboundAdmission&) -> InboundAdmission& = delete;

        InboundAdmission(InboundAdmission&& Other) noexcept;
        auto operator=(InboundAdmission&& Other) noexcept -> InboundAdmission&;
        ~InboundAdmission() noexcept;

        /**
         * @brief 在协议读取或握手前建立可重试关闭所有者；预约失败不启动握手。
         * @param Inbound 按值接收的共享传输 owner；成功时由票据保留一份引用。
         * @return 成功返回退休票据；空输入为 InvalidArgument，预约异常按 Failure 映射返回。
         *         预约失败会先尝试关闭并排空；清理失败不覆盖预约失败的首因。
         * @note 失败清理屏蔽协程取消，并由 inbound 的原 executor/Activity 完成 drain。
         */
        [[nodiscard]] static auto Prepare(Prism::SharedTransmission Inbound)
            -> Net::awaitable<PrepareResult>;

        /**
         * @brief 校验并发布唯一数据面；非法值先关闭并排空，失败继续保留预约票据。
         * @param Plane 按值接收的数据面及其协议/session owner。
         * @return 成功返回数据面的 owning 值并转移本票据；无票据为 InvalidArgument，Plane 校验
         *         失败返回 Validate 的原 Failure，且由本票据退休 Plane 和已登记资源。不完整退休会
         *         保留 owner 并在 inbound 原 executor 重试。
         * @note 失败退休不执行半关闭；本协程取消不会使已保留 owner 提前释放。
         */
        [[nodiscard]] auto Admit(ProtocolDataPlane Plane) -> Net::awaitable<Outcome>;

        /**
         * @brief 退休握手/识别拒绝时的输入并保留正式首因。
         * @param Failure 已发生的握手/识别失败；成功值会映射为 InvalidArgument。
         * @return 始终为拒绝结果；首因优先于清理错误，未完成清理的资源仍由票据保留并重试。
         * @note Cancel/Close 与 drain 由 inbound 原 executor owner 完成；不执行半关闭。
         */
        [[nodiscard]] auto Reject(Prism::Fault::Failure Failure) -> Net::awaitable<Outcome>;

        /**
         * @brief 协议已构造子所有者但后续应答失败时，一并退休数据面与租约。
         * @param Plane 按值接收并纳入本次失败退休的数据面。
         * @param Failure 已发生的协议/应答失败；成功值会映射为 InvalidArgument。
         * @return 始终为拒绝结果；保留 Failure 首因，未完成的关闭与 drain 继续由票据持有。
         * @note 无活动票据时返回 InvalidArgument。退休在 inbound 原 executor 驱动，不把取消当成关闭。
         */
        [[nodiscard]] auto Reject(
            ProtocolDataPlane Plane,
            Prism::Fault::Failure Failure) -> Net::awaitable<Outcome>;

        /**
         * @brief 完成非数据面工厂拒绝前的真实传输载体关闭与排空。
         * @param Failure 拒绝首因；Success 会映射为 InvalidArgument。
         * @return 返回本次拒绝的首因；Success 输入映射为 InvalidArgument。无状态时直接返回归一化
         *         的首因；清理错误不覆盖已有首因，未完成退休由同一票据保留并在原 executor 重试。
         * @note 本方法请求 Cancel/Close，不执行 stream 半关闭；底层最终关闭仍归实际传输 owner。
         */
        [[nodiscard]] auto Retire(Prism::Fault::Failure Failure)
            -> Net::awaitable<Prism::Fault::Failure>;

        /**
         * @brief 嵌套 StreamFactory 已接管失败退休责任后释放本层预约。
         * @details 只移交本票据保留的共享 owner，不发送 Cancel/Close、不等待 drain；调用者必须
         *          确认下层 owner 已接管相同资源的最终关闭与重试责任。
         */
        auto Release() noexcept -> void;

        /**
         * @brief 将握手期间新增的有限层级载体登记到预预约所有者。
         * @param Transport 借用共享 owner；票据保存一份引用，直到移交或真实退休。
         * @return 已登记、重复或 inbound 本身均成功；移动后/已释放对象无状态或 Transport 为空时返回
         *         InvalidArgument，固定槽耗尽返回 ResourceUnavailable。这里只登记，不发起关闭。
         */
        [[nodiscard]] auto Track(const Prism::SharedTransmission& Transport)
            -> std::expected<void, Prism::Fault::Failure>;

        /**
         * @brief 返回握手前登记的同一多路复用根创建票据，不分配或复制退休状态。
         * @return 返回当前持有的同一 shared owner；移动后或 Release/Abandon 后为空。它不复制退休状态，
         *         也不授予独立的物理关闭权。
         */
        [[nodiscard]] auto RootCreateOwner() const noexcept
            -> std::shared_ptr<MuxRootCreateOwner>;

        /**
         * @brief 在准入边界把异常映射为正式 Failure。
         * @param Exception 按值接收的异常指针；保留 system/Boost 原生错误，bad_alloc 映射为
         *        ResourceUnavailable，其它异常映射为 GenericError。
         * @return 不拥有资源、不执行关闭或 executor 调度的失败值。
         */
        [[nodiscard]] static auto ExceptionFailure(std::exception_ptr Exception) noexcept
            -> Prism::Fault::Failure;

    private:
        explicit InboundAdmission(std::shared_ptr<RetirementState> State);

        [[nodiscard]] static auto RetireUnreserved(
            const Prism::SharedTransmission& Inbound) -> Net::awaitable<AdmissionRetirementResult>;

        static auto PreserveFailure(
            Prism::Fault::Failure& Primary,
            const Prism::Fault::Failure& Secondary) noexcept -> void;

        static auto FailureFromException(std::exception_ptr Exception) noexcept
            -> Prism::Fault::Failure;

        auto Abandon() noexcept -> void;
        std::shared_ptr<RetirementState> State_;
    };
}
