/**
 * @file config.hpp
 * @brief smux 多路复用配置
 * @details 定义 smux 多路复用层的行为参数，包括最大流数、
 * 缓冲区大小和心跳间隔等。smux 配置允许在单个 TCP 连接上
 * 复用多个请求流，用于接受 Clash 等客户端的 mux 连接。
 *
 * @section overview 概述
 *
 * smux（simple multiplexing）是一种简单的多路复用协议，
 * 用于在单个 TCP 连接上承载多个独立的双向字节流。
 * 它的主要优势包括：
 * - **减少连接开销**：避免频繁的 TCP 握手
 * - **隐藏流量特征**：多请求共享连接，难以区分单个请求
 * - **提高连接效率**：长连接复用，减少延迟
 *
 * @note 默认配置适用于大多数场景，可根据实际需求调整
 */
#pragma once

#include <cstdint>

namespace ngx::channel::smux
{
    /**
     * @struct config
     * @brief smux 多路复用配置
     * @details 控制 smux 服务端的行为参数。启用 smux 后，
     * 服务端可以接受来自 Clash 等客户端的 mux 连接，
     * 并将其复用的多个流分别转发到目标服务器。
     *
     * @section stream_management 流管理
     *
     * smux 服务端管理多个并发流：
     * - 每个 SYN 帧创建一个新流
     * - 每个流独立连接目标服务器
     * - 流之间相互独立，互不影响
     *
     * @code
     * smux::config cfg;
     * cfg.enabled = true;
     * cfg.max_streams = 32;
     * cfg.buffer_size = 4096;
     * @endcode
     */
    struct config
    {
        /**
         * @brief 是否启用 smux 服务端
         * @details 默认禁用。启用后，检测到 Trojan MUX 命令时，
         * 将切换到 smux 模式处理多路复用连接。
         *
         * **启用条件**：
         * - Trojan 协议已启用
         * - 客户端发送 MUX 命令 (0x7f)
         *
         * **禁用时行为**：
         * - MUX 命令被视为普通连接
         */
        bool enabled = false;

        /**
         * @brief 最大并发流数
         * @details 限制单个 mux 会话上同时活跃的流数量。
         *
         * **流数限制原因**：
         * - 防止单个会话过载
         * - 限制内存使用
         * - 公平分配资源
         *
         * **配置建议**：
         * - 32：适合大多数场景
         * - 64+：高并发场景，需要更多内存
         */
        std::uint32_t max_streams = 32;

        /**
         * @brief 每流缓冲区大小（字节）
         * @details 每个流的数据缓冲区大小，影响内存占用和吞吐量。
         *
         * **配置建议**：
         * - 4096 (4KB)：默认值，适合大多数场景
         * - 8192+：大流量场景
         *
         * @note 总缓冲 ≈ buffer_size * 活跃流数
         */
        std::uint32_t buffer_size = 4096;

        /**
         * @brief 心跳间隔（毫秒）
         * @details 定期检查连接活跃状态。
         *
         * **工作流程**：
         * 1. 收到 PING 帧时立即回复 PONG
         * 2. 用于检测连接存活
         *
         * **配置建议**：
         * - 30000 (30秒)：适合大多数场景
         */
        std::uint32_t keepalive_interval_ms = 30000;

        /**
         * @brief UDP 管道空闲超时（毫秒）
         * @details UDP 管道在无数据传输时自动关闭的超时时间。
         * 每次收到客户端 PSH 数据报时重置计时器。
         * 默认 60000（60秒），适合 DNS 查询等短时 UDP 流。
         * 长时间 UDP 会话可设为 120000 以上。
         */
        std::uint32_t udp_idle_timeout_ms = 60000;

        /**
         * @brief UDP 数据报最大长度（字节）
         * @details 限制单个 UDP 数据报的编码后最大长度。
         * SOCKS5 UDP 头部最多增加 26 字节（IPv6），
         * 实际 payload 最大为 udp_max_datagram - 26。
         */
        std::uint32_t udp_max_datagram = 65535;
    };
} // namespace ngx::channel::smux
