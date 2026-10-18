/** @file PacketTransferResult.hpp @brief 协议数据报的载荷与 wire 传输结果。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <cstddef>

namespace Prism::Contract::Io
{
    /**
     * @brief 一次协议数据报操作的完成载荷、实际帧字节与完整失败事实。
     * @details PayloadBytes 仅在完整数据报成功交付/消费时为载荷长度；失败时保持零。
     *          WireBytes 是本次帧在 carrier 上真实读写的累计字节，含协议帧头和认证字节。
     *          空数据报成功表现为 PayloadBytes 为零、Failure 成功且 WireBytes 非零；干净 EOF
     *          由 Failure.Code 表示，不能从空载荷推断。类型不拥有缓冲区、不发起 I/O，也不
     *          执行取消、半关闭或最终关闭；这些行为由协议连接 owner 在其固定 executor 上负责。
     */
    struct PacketTransferResult final
    {
        std::size_t PayloadBytes{0}; ///< 完整成功数据报的载荷字节数。
        std::size_t WireBytes{0}; ///< 当前数据报帧已真实传输的 wire 字节数。
        Prism::Fault::Failure Failure{}; ///< 失败类别及原生 category/value，原样保留。

        [[nodiscard]] auto Succeeded() const noexcept -> bool
        {
            return Failure.Succeeded();
        }

        [[nodiscard]] auto Failed() const noexcept -> bool
        {
            return Failure.Failed();
        }
    };
} // namespace Prism::Contract::Io
