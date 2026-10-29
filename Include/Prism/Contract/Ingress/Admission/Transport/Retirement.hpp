/** @file Retirement.hpp @brief 单条入站传输的真实 close/drain 回执。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/awaitable.hpp>
#include <exception>

namespace Prism::Contract
{
    namespace Net = boost::asio;

    /**
     * @brief 一次入站资源退休的物理完成事实与首个操作错误。
     * @details Complete 只表示真实 owner 已退休；Error 保留首个 typed/native Failure，二者可同时成立，
     *          例如取消结果到达时物理退休已完成。
     */
    struct AdmissionRetirementResult final
    {
        bool Complete{true};
        Prism::Fault::Failure Error{};
    };

    /**
     * @brief 保留最先出现的非成功原因，不合并或覆盖 Native。
     * @param Primary 按引用更新的首因；已有 Failure 时保持不变。
     * @param Next 后续观察到的 Failure；仅在 Primary 成功时接管。
     * @note 纯值操作，不调度 executor，也不关闭资源。
     */
    inline auto PreserveAdmissionFailure(
        Prism::Fault::Failure &Primary,
        const Prism::Fault::Failure &Next) noexcept -> void
    {
        if (!Primary.Failed() && Next.Failed()) Primary = Next;
    }

    /**
     * @brief 合并退休事实并保留首个操作错误。
     * @param Primary 按引用更新的累计结果。
     * @param Next 本次 drain/close 的结果。
     * @details Primary.Complete 取两者逻辑与；Primary.Error 取最先出现的 Failure。
     */
    inline auto MergeAdmissionRetirementResult(
        AdmissionRetirementResult &Primary,
        const AdmissionRetirementResult &Next) noexcept -> void
    {
        Primary.Complete = Primary.Complete && Next.Complete;
        PreserveAdmissionFailure(Primary.Error, Next.Error);
    }

    /**
     * @brief 将异常映射为 typed Failure，并保留可用的 system/Boost 原生 cause。
     * @param Exception 按值接收的当前异常指针。
     * @return system_error 保留 Native；bad_alloc 映射 ResourceUnavailable；其它异常或空指针映射 GenericError。
     * @note 不拥有资源，不执行 executor 调度或关闭。
     */
    [[nodiscard]] auto AdmissionFailureFromException(std::exception_ptr Exception) noexcept
        -> Prism::Fault::Failure;

    /**
     * @brief 只封止并等待原 transport activity 真实退栈，不发送 Cancel/Close。
     * @param Transport 借用的共享传输 owner；调用者须在 await 返回前保留该 owner。
     * @return 空传输为已完成；缺少 Activity 或仍未退休时 Complete=false 并带 Failure。Drain 的
     *         首个错误保留在 Error；Activity 可在返回错误时仍报告物理退休已完成。
     * @note 本函数不切换 executor、不做半关闭或最终关闭；实际 drain/executor 由 Activity owner 实现。
     */
    [[nodiscard]] auto DrainAdmissionTransport(
        const Prism::SharedTransmission &Transport)
        -> Net::awaitable<AdmissionRetirementResult>;

    /**
     * @brief 对单条 carrier 只请求一次 Cancel/Close，随后等待真实 Activity drain。
     * @param Transport 借用的共享传输 owner；调用者须持有它直到真实退休或后续重试结束。
     * @param CancelAttempted 调用者拥有的跨重试状态；函数在首次调用 Cancel 前置为 true。
     * @param CloseAttempted 调用者拥有的跨重试状态；函数在首次调用 Close 前置为 true。
     * @return Complete 表示 Activity 已真实退休；Error 保留首个 Cancel/Close/drain Failure。空传输视为完成。
     * @note 不自行切换 executor、屏蔽等待取消或执行半关闭；await 被取消时两项 attempt 状态仍保留，
     *       调用者必须保活传输与状态并再次调用以继续 drain。物理最终关闭仍归 Transmission/协议 owner。
     */
    [[nodiscard]] auto RetireAdmissionTransport(
        const Prism::SharedTransmission &Transport,
        bool &CancelAttempted,
        bool &CloseAttempted)
        -> Net::awaitable<AdmissionRetirementResult>;
}
