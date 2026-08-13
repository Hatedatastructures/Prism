/**
 * @file trojan.hpp
 * @brief Trojan 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：connect / connect_packet（客户端）、
 *   accept / accept_packet（服务端）——握手在工厂内部完成
 * - 配置：client_config（client.hpp）、server_config（server.hpp）
 * - 连接：conn（流，conn.hpp）、dgram（包，dgram.hpp）
 * - 编解码（codec.hpp）、纯数据（types.hpp）
 * @note 对齐 mihomo/sing-*：TCP 流与 UDP 包为两种独立连接类型；
 *          工厂自由函数承担"创建 + 装配 + 握手编排"。
 * @note span 参数为视图（不持有生命周期），连接所有权经 shared_ptr
 *          管理；close() 同步关闭，release() 可转移所有权。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/proxy/trojan/codec.hpp>
#include <common/proxy/trojan/conn.hpp>
#include <common/proxy/trojan/dgram.hpp>
#include <common/proxy/trojan/types.hpp>

namespace psmtest::trojan
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct client_config
     * @brief Trojan 客户端配置
     * @details 控制客户端的行为：密码（凭据派生）。构造后只读。
     */
    struct client_config
    {
        /// 客户端密码（连接构造时派生 SHA224 hex 凭据）
        std::string password;
    };

    /**
     * @struct server_config
     * @brief Trojan 服务端配置
     * @details 控制服务端的行为：密码（凭据派生）与命令开关。
     * 构造后只读。
     */
    struct server_config
    {
        /// 服务端密码（连接构造时派生 SHA224 hex 凭据）
        std::string password;
        /// 是否允许 CONNECT 命令（TCP 转发）
        bool enable_tcp = true;
        /// 是否允许 UDP_ASSOCIATE 命令（UDP 中继）
        bool enable_udp = false;
    };

    /**
     * @brief 创建客户端流连接并完成握手（sing DialConn 语义）
     * @tparam T 传输类型（transmission_like 约束）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param target 目标地址
     * @param cmd 命令（默认 CONNECT；UDP 场景传 udp_associate）
     * @return 错误码与协议连接（失败时连接为空）
     * @details 内部流程：创建 conn → 注入凭据 → write_handshake 发送
     * 请求头（握手对调用方透明）。成功后连接持有 upstream。
     */
    [[nodiscard]] inline auto connect(shared_transmission upstream, const client_config &cfg,
                                      const address &target, command cmd = command::connect)
        -> net::awaitable<std::pair<error, shared_conn>>
    {
        auto c = std::make_shared<conn>(std::move(upstream), cfg.password);
        const auto err = co_await c->write_handshake(target, cmd);
        co_return std::pair{err, err == error::none ? shared_conn(std::move(c)) : shared_conn{}};
    }

    /**
     * @brief 创建客户端 UDP 包连接并完成 udp_associate 握手
     * @tparam T 传输类型（transmission_like 约束）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param target 目标地址
     * @return 错误码与包连接（失败时连接为空）
     * @details 先经 connect 完成 udp_associate 握手，再包装为
     * 包连接（对齐 mihomo ListenPacketContext：握手后 NewPacketConn）。
     */
    [[nodiscard]] inline auto connect_packet(shared_transmission upstream, const client_config &cfg,
                                             const address &target)
        -> net::awaitable<std::pair<error, shared_dgram>>
    {
        auto [err, conn] = co_await connect(std::move(upstream), cfg, target, command::udp_associate);
        if (err != error::none)
        {
            co_return std::pair{err, shared_dgram{}};
        }
        co_return std::pair{error::none, std::make_shared<dgram>(std::move(conn))};
    }

    /**
     * @brief 接收服务端流连接并完成握手（sing Service 语义）
     * @tparam T 传输类型（transmission_like 约束）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     * @details 内部流程：创建 conn → 注入凭据 → read_handshake 解析
     * 请求头（凭据/CRLF/命令开关/atyp/尾部校验）。认证失败不发送
     * 响应，静默断开。
     */
    [[nodiscard]] inline auto accept(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::tuple<error, request_header, shared_conn>>
    {
        auto c = std::make_shared<conn>(std::move(upstream), cfg.password);
        auto [err, req] = co_await c->read_handshake(cfg.enable_tcp, cfg.enable_udp);
        co_return std::tuple{err, std::move(req),
                             err == error::none ? shared_conn(std::move(c)) : shared_conn{}};
    }

    /**
     * @brief 接收服务端 UDP 包连接（UDP_ASSOCIATE 命令）
     * @tparam T 传输类型（transmission_like 约束）
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与包连接（失败时连接为空）
     * @details 先经 accept 完成流握手解析，再包装为包连接。
     */
    [[nodiscard]] inline auto accept_packet(shared_transmission upstream, const server_config &cfg)
        -> net::awaitable<std::tuple<error, request_header, shared_dgram>>
    {
        auto [err, req, conn] = co_await accept(std::move(upstream), cfg);
        if (err != error::none)
        {
            co_return std::tuple{err, std::move(req), shared_dgram{}};
        }
        co_return std::tuple{error::none, std::move(req), std::make_shared<dgram>(std::move(conn))};
    }

} // namespace psmtest::trojan
