/**
 * @file Context.hpp
 * @brief 中间件管线上下文
 * @details 在中间件链中传递的共享状态：目标地址、流量统计、
 * 传输所有权、检测结果、填充配置等。对应生产库 forward_pipeline
 * 的 pipeline_options 职责。
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#include <boost/asio/awaitable.hpp>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Net/Target.hpp>
#include <common/Core/Transmission.hpp>

namespace Preview::Middleware
{

    /**
     * @class Context
     * @brief 管线执行上下文
     * @details 持有管线内共享的数据：入站传输（可被中间件替换）、
     * 目标地址、协议检测结果、流量统计指针。中间件通过修改
     * Inbound 实现"包装"语义（如 pad/mux 装饰）。
     */
    class Context
    {
    public:
        /// 入站传输（中间件可替换包装）
        Preview::SharedTransmission Inbound;
        /// 上游传输（Dial 中间件产出，relay 中间件消费）
        Preview::SharedTransmission Outbound;
        /// 目标地址（拨号中间件消费）
        Preview::Network::Target Target;
        /// 检测到的协议类型
        std::uint16_t detected{0};
        /// Dgram 会话标记（AcceptProtocol 设置；Session 转走 udp_service）
        bool IsDgram{false};
        /// 流量统计回调（relay 中间件消费）
        struct TrafficSink
        {
            /// 上报流量
            virtual auto Report(std::string_view identity, std::size_t up, std::size_t down) -> void = 0;
            virtual ~TrafficSink() = default;
        };
        TrafficSink *traffic{nullptr};
        /// 认证通过后的用户标识（Auth 中间件写入，relay 统计按此聚合）
        std::string identity{};
        /// 原始凭据（Auth 中间件默认提取：identity + Secret）
        std::string RawIdentity{};
        std::string RawSecret{};
        /// 填充配置（可选，pad 中间件消费）
        struct PadConfig
        {
            bool Enabled{false};
            std::size_t MinSize{64};
            std::size_t MaxSize{1024};
        };
        const PadConfig *pad{nullptr};
        /// 缓冲区大小（relay 中间件消费）
        std::size_t BufferSize{16384};
        /// 管线空闲超时（>0 时 relay 优先使用；0 = 用 relay 构造参数）
        std::chrono::milliseconds timeout{0};
        /// 拨号完成回调（协议注入：拨号成功/失败后发送协议级应答）
        std::function<boost::asio::awaitable<void>(Preview::Fault::Code)> PostDial{};
    };

} // namespace Preview::Middleware
