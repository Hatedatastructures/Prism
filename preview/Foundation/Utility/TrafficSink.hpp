/**
 * @file TrafficSink.hpp
 * @brief 流量统计回调接口
 * @details 定义协议数据面与运行时统计之间的最小契约。
 *          协议只依赖该接口，不依赖运行时上下文。
 */
#pragma once

#include <cstddef>
#include <string_view>

namespace Preview::Foundation
{

    /**
     * @struct TrafficSink
     * @brief 流量统计回调接口
     * @details 数据面在会话结束或数据报服务收口时上报身份、
     *          上行字节数和下行字节数。接口不拥有实现对象。
     */
    struct TrafficSink
    {
        virtual ~TrafficSink() = default;

        /**
         * @brief 上报一次流量统计
         * @param Identity 统计身份，调用期间保持有效
         * @param Up 上行字节数
         * @param Down 下行字节数
         */
        virtual auto Report(std::string_view Identity, std::size_t Up,
                            std::size_t Down) -> void = 0;
    };

} // namespace Preview::Foundation
