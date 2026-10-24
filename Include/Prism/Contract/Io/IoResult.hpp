/** @file IoResult.hpp @brief 流 I/O 已完成字节及独立失败事实。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <cstddef>

namespace Prism
{
    /**
     * @brief 一次实际 read/write completion 的纯值结果。
     * @details Bytes 是已交付或已写入的真实字节，Failure 可同时携带 EOF/原生错误；
     *          调用者必须先消费已完成字节，再处理终态，不能因失败把 Bytes 清零。
     *          零字节成功不隐含 EOF。值不拥有 buffer，借用期限到 operation completion；
     *          取消、半关闭和最终关闭由实际载体 owner 执行，结果可跨 executor 复制。
     */
    struct IoResult final
    {
        std::size_t Bytes{0}; ///< 本次操作实际完成的字节数。
        Prism::Fault::Failure Failure{}; ///< 同次完成的领域类别及原生 category/value。
    };
}
