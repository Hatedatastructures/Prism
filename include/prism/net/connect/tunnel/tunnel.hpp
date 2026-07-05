/**
 * @file tunnel.hpp
 * @brief 隧道转发
 * @details 双向透明转发功能，在两个传输流之间建立全双工隧道。
 */
#pragma once

#include <prism/context/flow_opts.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/proto/protocol/types.hpp>

#include <boost/asio.hpp>

#include <cstdint>

namespace psm
{
    namespace account { class lease; }
    namespace stats::traffic { class traffic_state; }
}

namespace psm::transport
{
    struct pad_config;
}


namespace psm::connect
{

    namespace net = boost::asio;
    using shared_transmission = transport::shared_transmission;

    /**
     * @brief 隧道写入策略
     * @details 控制隧道转发时使用完整写入还是部分写入语义。
     */
    enum class write_policy : std::uint8_t
    {
        partial,  ///< 部分写入，使用 async_write_some
        complete  ///< 完整写入，使用 async_write 确保全部数据写入
    };

    /**
     * @struct tunnel_options
     * @brief 隧道转发选项
     * @details 继承 flow_opts 获取 trace/cfg/rt 通用字段，
     * 组合双向隧道转发所需的全部参数。
     */
    struct tunnel_options : public psm::context::flow_opts
    {
        shared_transmission inbound;                            ///< 入站流对象
        shared_transmission outbound;                           ///< 出站流对象
        write_policy policy{write_policy::complete};            ///< 写入策略
        const transport::pad_config *pad_cfg{nullptr};          ///< 填充配置
        stats::traffic::traffic_state *traffic{nullptr};        ///< 流量统计（替代 ctx.worker_ctx.traffic）
        account::lease *lease{nullptr};                         ///< 账户租约（替代 ctx.account_lease）

        /// 兼容旧测试：{inbound, outbound, buffer_size, policy}
        tunnel_options(shared_transmission in, shared_transmission out,
                       std::uint32_t buf_size, write_policy pol = write_policy::complete)
            : inbound(std::move(in)), outbound(std::move(out)),
              policy(pol), buffer_size(buf_size) {}

        tunnel_options() = default;
        protocol::protocol_type detected{protocol::protocol_type::unknown}; ///< 检测到的协议
        std::uint32_t buffer_size{0};                            ///< 缓冲区大小（替代 ctx.buffer_size）
    };

    /**
     * @brief 在两个流之间运行全双工隧道
     * @param opts 隧道选项（入站/出站流、上下文、写入策略）
     * @return 协程对象，隧道结束后完成
     * @details 建立双向数据转发隧道，同时处理入站到出站和出站到入站
     * 的数据流。任一方向断开即终止整个隧道。隧道结束后自动关闭两端的连接。
     * @note 缓冲区大小至少为 2 字节，实际使用时建议不小于 64KB。
     */
    auto tunnel(tunnel_options opts) -> net::awaitable<void>;

} // namespace psm::connect
