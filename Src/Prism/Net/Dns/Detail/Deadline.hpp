/**
 * @file Deadline.hpp
 * @brief DNS 尝试级绝对 deadline 与连接 deadline 定时器 owner
 * @details 一次上游尝试只创建一个 AttemptDeadline，端点解析、建连、收发和
 *          DoH 分块读写共享同一绝对时刻。每个 I/O 操作用 DeadlineScope
 *          武装该连接自己的定时器：
 *          - 定时器 handler 持有真实共享连接状态，不借用裸 this；操作取消、
 *            对象析构和迟到完成都不会触碰已释放对象
 *          - 每次武装分配一个代次；解除武装或重新武装立即作废旧代次已排队
 *            的成功回调（终态 CAS 语义），池化连接复用不会被迟到回调误伤
 *          - 到期由 handler 取消本连接在途 I/O 并记录到期代次，供把中止
 *            映射为明确的 Timeout；外部取消保持 operation_aborted
 * @note 非线程安全，与 DNS 模块一致，单 io_context 内使用
 */

#pragma once

#include <Prism/Net/Dns/AttemptDeadline.hpp>
#include <Prism/Foundation/Error.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <concepts>
#include <cstdint>
#include <memory>
#include <utility>

namespace Prism::Network::Dns::Detail
{

    namespace Net = boost::asio;

    /**
     * @struct DeadlineState
     * @brief 连接级 deadline 定时器与代次
     * @details 每个连接状态内嵌一份；代次让迟到回调按终态作废，
     *          等价于弱引用加终态 CAS，但连接真正由共享状态持有。
     */
    struct DeadlineState
    {
        /**
         * @brief 构造定时器
         * @param Executor 连接所用执行器
         */
        explicit DeadlineState(Net::any_io_executor Executor) : Timer(std::move(Executor)) {}

        Net::steady_timer Timer;     ///< 本连接当前操作的 deadline 定时器
        std::uint64_t Epoch{0};      ///< 当前操作代次；每次武装/解除都递增
        std::uint64_t FiredEpoch{0}; ///< 真正到期并取消过 I/O 的代次
    };

    /// deadline 武装要求：连接状态内嵌 Deadline 定时器并提供在途 I/O 取消
    template <typename T>
    concept DeadlineTarget = requires(T StateObject, boost::system::error_code &ErrorCode) {
        StateObject.Deadline.Timer;
        StateObject.CancelPending(ErrorCode);
    };

    /**
     * @brief deadline 定时器完成：到期取消本连接在途 I/O
     * @param StateValue 真实共享连接状态
     * @param Epoch 武装时的操作代次
     * @param ErrorCode 定时器完成码
     */
    template <DeadlineTarget State>
    auto OnDeadlineFired(const std::shared_ptr<State> &StateValue, const std::uint64_t Epoch,
                         const boost::system::error_code ErrorCode) -> void
    {
        if (ErrorCode)
        {
            return; // 已解除或重新武装：本代次不再有动作
        }
        if (Epoch != StateValue->Deadline.Epoch)
        {
            return; // 迟到成功回调：操作已被新代次取代，不能触碰当前 I/O
        }
        StateValue->Deadline.FiredEpoch = Epoch;
        boost::system::error_code Ignore;
        StateValue->CancelPending(Ignore);
    }

    /**
     * @brief 以绝对 deadline 武装定时器
     * @param StateValue 真实共享连接状态；handler 持同一 owner
     * @param Deadline 本次尝试的绝对截止时刻
     * @return 本次武装的代次；解除武装后该代次立即作废
     */
    template <DeadlineTarget State>
    [[nodiscard]] auto ArmDeadline(const std::shared_ptr<State> &StateValue,
                                   const AttemptDeadline Deadline) -> std::uint64_t
    {
        auto &Watch = StateValue->Deadline;
        const auto Epoch = ++Watch.Epoch;
        Watch.Timer.expires_at(Deadline.At());
        Watch.Timer.async_wait(
            [StateValue, Epoch](const boost::system::error_code ErrorCode)
            { OnDeadlineFired(StateValue, Epoch, ErrorCode); });
        return Epoch;
    }

    /**
     * @brief 解除武装并作废本代次已排队的回调
     * @param StateValue 真实共享连接状态
     */
    template <DeadlineTarget State>
    auto DisarmDeadline(const std::shared_ptr<State> &StateValue) -> void
    {
        StateValue->Deadline.Timer.cancel();
        ++StateValue->Deadline.Epoch;
    }

    /**
     * @brief 映射本连接 deadline 错误
     * @param ErrorCode 底层 I/O 错误
     * @param StateValue 真实共享连接状态
     * @param Epoch 当前操作代次
     * @return 本连接 deadline 触发的取消返回 Timeout；外部取消保持原错误
     */
    template <DeadlineTarget State>
    [[nodiscard]] auto MapDeadlineError(const boost::system::error_code ErrorCode,
                                        const std::shared_ptr<State> &StateValue,
                                        const std::uint64_t Epoch) -> boost::system::error_code
    {
        if (ErrorCode == Net::error::operation_aborted && StateValue->Deadline.FiredEpoch == Epoch)
        {
            return make_error_code(Error::Timeout);
        }
        return ErrorCode;
    }

    /**
     * @class DeadlineScope
     * @brief 一次 I/O 的 deadline 作用域：构造武装、析构解除
     * @details 作用域内所有 I/O 段共享同一绝对 deadline；即使协程帧在挂起
     *          中被销毁，析构仍只触碰共享状态，迟到回调按代次作废。
     */
    template <DeadlineTarget State>
    class DeadlineScope
    {
    public:
        /**
         * @brief 武装本次操作的 deadline
         * @param StateValue 真实共享连接状态
         * @param Deadline 本次尝试的绝对截止时刻
         */
        DeadlineScope(std::shared_ptr<State> StateValue, const AttemptDeadline Deadline)
            : State_(std::move(StateValue)), Epoch_(ArmDeadline(State_, Deadline))
        {
        }

        DeadlineScope(const DeadlineScope &) = delete;
        auto operator=(const DeadlineScope &) -> DeadlineScope & = delete;
        DeadlineScope(DeadlineScope &&) = delete;
        auto operator=(DeadlineScope &&) -> DeadlineScope & = delete;

        ~DeadlineScope()
        {
            DisarmDeadline(State_);
        }

        /**
         * @brief 本代次 I/O 错误的正式值
         * @param ErrorCode 底层 I/O 错误
         * @return deadline 到期导致的取消映射为 Timeout，其余原样返回
         */
        [[nodiscard]] auto Map(const boost::system::error_code ErrorCode) const
            -> boost::system::error_code
        {
            return MapDeadlineError(ErrorCode, State_, Epoch_);
        }

    private:
        std::shared_ptr<State> State_;
        std::uint64_t Epoch_{0};
    };

} // namespace Prism::Network::Dns::Detail
