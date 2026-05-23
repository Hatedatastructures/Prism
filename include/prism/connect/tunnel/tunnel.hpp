/**
 * @file tunnel.hpp
 * @brief 隧道转发
 * @details 双向透明转发功能，在两个传输流之间建立全双工隧道。
 */
#pragma once

#include <boost/asio.hpp>
#include <prism/context/context.hpp>
#include <prism/transport/transmission.hpp>

namespace psm::connect
{
    namespace net = boost::asio;
    using shared_transmission = transport::shared_transmission;

    /**
     * @brief 在两个流之间运行全双工隧道
     * @param inbound 入站流对象
     * @param outbound 出站流对象
     * @param ctx 会话上下文，提供内存资源和缓冲区配置
     * @param complete_write 是否使用完整写入语义（默认 true）
     * @return 协程对象，隧道结束后完成
     * @details 建立双向数据转发隧道，同时处理入站到出站和出站到入站
     * 的数据流。任一方向断开即终止整个隧道。隧道结束后自动关闭两端的连接。
     * @note 缓冲区大小至少为 2 字节，实际使用时建议不小于 64KB。
     */
    auto tunnel(shared_transmission inbound, shared_transmission outbound, const context::session &ctx, bool complete_write = true)
        -> net::awaitable<void>;

} // namespace psm::connect
