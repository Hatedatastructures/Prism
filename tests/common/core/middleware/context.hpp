/**
 * @file context.hpp
 * @brief 中间件管线上下文
 * @details 在中间件链中传递的共享状态：目标地址、流量统计、
 * 传输所有权、检测结果、填充配置等。对应生产库 forward_pipeline
 * 的 pipeline_options 职责。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include <common/core/protocol/target.hpp>
#include <common/core/transmission.hpp>

namespace psmtest::middleware
{

    /**
     * @class context
     * @brief 管线执行上下文
     * @details 持有管线内共享的数据：入站传输（可被中间件替换）、
     * 目标地址、协议检测结果、流量统计指针。中间件通过修改
     * inbound 实现"包装"语义（如 pad/mux 装饰）。
     */
    class context
    {
    public:
        /// 入站传输（中间件可替换包装）
        psmtest::shared_transmission inbound;
        /// 上游传输（dial 中间件产出，relay 中间件消费）
        psmtest::shared_transmission outbound;
        /// 目标地址（拨号中间件消费）
        psmtest::connect::target target;
        /// 检测到的协议类型
        std::uint16_t detected{0};
        /// 流量统计回调（relay 中间件消费）
        struct traffic_sink
        {
            /// 上报流量
            /// �ϱ�����（�� identity ���������ˣ�
            virtual auto report(std::string_view identity, std::size_t up, std::size_t down) -> void = 0;
            virtual ~traffic_sink() = default;
        };
        traffic_sink *traffic{nullptr};
        /// 认证通过后的用户标识（auth 中间件写入，relay 统计按此聚合）
        std::string identity{};
        /// 填充配置（可选，pad 中间件消费）
        struct pad_config
        {
            bool enabled{false};
            std::size_t min_size{64};
            std::size_t max_size{1024};
        };
        const pad_config *pad{nullptr};
        /// 缓冲区大小（relay 中间件消费）
        std::size_t buffer_size{16384};
    };

} // namespace psmtest::middleware
