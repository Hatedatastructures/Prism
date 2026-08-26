/**
 * @file Types.hpp
 * @brief 多路复用框架共享基础类型
 * @details 会话级控制帧分类与流事件枚举，
 *          供共享会话框架（Session.hpp）与帧策略（Codec.hpp）使用。
 */

#pragma once

#include <cstdint>

namespace Preview::Mux
{

    /// 流事件（会话框架分发用）
    enum class StreamEvent
    {
        /// 新建流（SYN / 隐式开流）
        Open,
        /// 数据到达
        Data,
        /// 半关（FIN）
        Fin,
        /// 重置（RST）
        Rst,
    };

} // namespace Preview::Mux