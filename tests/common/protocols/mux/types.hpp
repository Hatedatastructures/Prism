/**
 * @file types.hpp
 * @brief 多路复用框架共享基础类型
 * @details 会话级控制帧分类与流事件枚举，
 *          供共享会话框架（session.hpp）与帧策略（codec.hpp）使用。
 */

#pragma once

#include <cstdint>

namespace preview::mux
{

    /// 流事件（会话框架分发用）
    enum class stream_event
    {
        /// 新建流（SYN / 隐式开流）
        open,
        /// 数据到达
        data,
        /// 半关（FIN）
        fin,
        /// 重置（RST）
        rst,
    };

} // namespace preview::mux
