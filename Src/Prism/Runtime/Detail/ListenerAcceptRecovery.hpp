/**
 * @file ListenerAcceptRecovery.hpp
 * @brief TcpListener accept 错误分类与退避策略。
 * @details 监听 socket 在 fd 耗尽或对端建连放弃时仍然有效；把这类错误交给
 *          accept 循环退避重试，避免一次瞬时故障把服务永久置为不监听状态。
 */

#pragma once

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <cstddef>

namespace Prism::Runtime::Detail
{

    /**
     * @brief 判定 accept 错误是否属于本地资源瞬时耗尽。
     * @param Error accept 返回的原生错误。
     * @return fd 或内核缓冲短缺时返回 true；这类错误必须退避后重试。
     */
    [[nodiscard]] auto IsAcceptResourceExhaustion(const boost::system::error_code Error) noexcept
        -> bool;

    /**
     * @brief 判定 accept 错误能否在不关闭监听 socket 的前提下重试。
     * @param Error accept 返回的原生错误。
     * @return 对端建连放弃（RST/中断）或本地资源耗尽时返回 true。
     * @details 只有返回 false 的错误才应终止 accept 循环。
     */
    [[nodiscard]] auto IsRecoverableAcceptError(const boost::system::error_code Error) noexcept
        -> bool;

    /**
     * @brief 计算资源耗尽后的退避时长。
     * @param ConsecutiveFailures 连续失败次数。
     * @return 从 2ms 起按 2 的幂增长、封顶 1 秒的等待时长。
     * @details 封顶避免 fd 长期短缺时把 accept 协程钉在长睡眠上。
     */
    [[nodiscard]] auto AcceptBackoffDelay(const std::size_t ConsecutiveFailures) noexcept
        -> std::chrono::milliseconds;

} // namespace Prism::Runtime::Detail
