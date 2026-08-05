/**
 * @file egress.hpp
 * @brief 流数据出口抽象接口
 * @details 定义 multiplex::egress，stream/datagram 把数据交还会话层的
 *          唯一通道。替代旧设计中的 owner_ 弱引用 + core 虚函数依赖，
 *          实现 I/O 管道与协议会话的解耦：stream/datagram 只认识
 *          egress 接口，不感知任何具体协议类型，可独立测试。
 *          相当于一个"出口信箱"：管道把数据投进信箱，
 *          会话层负责把信件（数据）编码成帧发往客户端。
 * @note 线程安全：单个实例非线程安全，应在同一 executor 上串行使用
 * @note 生命周期：multiplexer 实现本接口；stream/datagram 持 weak_ptr<egress>
 *       防循环引用（会话持有管道 shared_ptr，管道持有出口弱引用）
 */
#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/net/connect/types.hpp>

#include <boost/asio.hpp>

#include <cstdint>


namespace psm::multiplex
{

    namespace net = boost::asio;

    /**
     * @class egress
     * @brief 流数据出口抽象
     * @details 定义从 I/O 管道到会话层的两个回传通道：
     *          send() 回传数据载荷，fin() 通知会话层对端流已结束。
     *          由 multiplexer 实现，stream/datagram 通过它把数据
     *          编码为协议帧发往客户端。
     */
    class egress
    {
    public:
        virtual ~egress() = default;

        /**
         * @brief 回传流数据（所有权转移，零拷贝）
         * @param stream_id 流标识符
         * @param payload 待发送的数据载荷
         * @return 异步操作，完成表示数据已投递至会话层发送通道
         */
        virtual auto send(std::uint32_t stream_id, memory::vector<std::byte> payload)
            -> net::awaitable<void> = 0;

        /**
         * @brief 通知会话层该流已结束（半关闭）
         * @param stream_id 流标识符
         */
        virtual void fin(std::uint32_t stream_id) = 0;

        /**
         * @brief 查询会话层是否仍活跃
         * @return true 会话活跃，可继续发送数据
         */
        [[nodiscard]] virtual auto active() const noexcept -> bool = 0;

        /**
         * @brief 上报流累计流量
         * @param up 上行（发送方向）字节数
         * @param down 下行（接收方向）字节数
         * @details 管道关闭时调用，会话层累加进总流量统计。
         */

        /**
         * @brief 通知会话层从注册表移除该流
         * @param stream_id 流标识符
         * @details 管道自行关闭（错误/EOF）时调用，会话层清理对应条目。
         */
        virtual void drop(std::uint32_t stream_id) = 0;
    };

} // namespace psm::multiplex
