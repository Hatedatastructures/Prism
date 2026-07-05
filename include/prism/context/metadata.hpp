/**
 * @file metadata.hpp
 * @brief 请求业务数据载体
 * @details 对标 mihomo 的 *Metadata。承载单条请求的业务上下文，
 * 从 L1 入口层构造，在 L2 各业务层流转。每层可读可填：
 * - L1（launch）填 src/dst/conn_id/inbound_tag
 * - L2 recognition 填 detected/sni/sniff_host
 * - L2 handler 填 target_host/target_port/user
 * - L2 dialer/router 填 outbound_tag/matched_rule
 *
 * 所有权：shared_ptr 管理。session 持有原始 shared_ptr，
 * 所有下游（包括 detached 协程）通过 shared_ptr 副本持有，
 * 避免 use-after-free。
 *
 * 与 trace_context 的区别：
 * - metadata 持业务数据（端点/目标/路由决策）
 * - trace_context 持日志渲染字段（conn_id/stream_id/scheme/phase）
 * 两者独立流转，但通常同时传递。
 */
#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/proto/protocol/types.hpp>

#include <boost/asio.hpp>

#include <cstdint>

namespace psm::context
{

    namespace net = boost::asio;

    /**
     * @struct request_metadata
     * @brief 请求业务数据载体（per-connection）
     * @details 对标 mihomo 的 *Metadata。从 L1 构造，在 L2 各层流转，
     * 每层可读可填。shared_ptr 管理，detached 协程安全。
     */
    struct request_metadata
    {
        // ── 网络（L1 填）──
        std::uint64_t conn_id{0};              ///< 连接唯一标识
        net::ip::tcp::endpoint src;            ///< 客户端端点
        net::ip::tcp::endpoint dst;            ///< 监听端点
        bool is_udp{false};                    ///< UDP 标志

        // ── 协议（L2 识别后填）──
        protocol::protocol_type detected{protocol::protocol_type::unknown};
        memory::string target_host;            ///< 目标主机（handler 填）
        std::uint16_t target_port{0};          ///< 目标端口
        memory::string sni;                    ///< TLS SNI
        memory::string sniff_host;             ///< 主动探测识别

        // ── 代理链（L2 流转填）──
        memory::string inbound_tag;            ///< 入站标签
        memory::string outbound_tag;           ///< 出站标签（router 填）
        memory::string matched_rule;           ///< 匹配的规则（router 填）

        // ── 认证（handler 填）──
        memory::string user;                   ///< 认证用户名

        // ── 探测追踪（L1 填）──
        std::array<std::byte, 16> src_ip_raw{}; ///< 来源 IP 哈希（RFC-065）
    };

} // namespace psm::context
