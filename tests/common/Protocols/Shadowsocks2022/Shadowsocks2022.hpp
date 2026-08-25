/**
 * @file shadowsocks2022.hpp
 * @brief Shadowsocks 2022 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，chunk 加解密数据面）、
 *   Dgram（包，Dgram.hpp，逐包 AEAD）
 * - 编解码/密码学：Codec.hpp（头部编解码 + KDF + chunk + 握手 + UDP 数据报）
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <openssl/evp.h>

#include <cstddef>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Core/Transport/Unreliable.hpp>
#include <common/Protocols/Shadowsocks2022/Conn.hpp>
#include <common/Protocols/Shadowsocks2022/Dgram.hpp>
#include <common/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    namespace ss = Preview::Shadowsocks2022;

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief SS2022 客户端配置
     * @details 控制客户端的行为：密码（PSK 派生）。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端密码（连接构造时派生 16 字节 PSK）
        std::string password;
        /// 直接指定 16 字节 PSK（标准配置：base64 psk 解码后原始字节，优先于 password）
        bool UsePsk{false};
        std::array<std::uint8_t, 16> psk{};
    };

    /**
     * @struct ServerConfig
     * @brief SS2022 服务端配置
     * @details 控制服务端的行为：密码（PSK 派生）与时间戳窗口。
     * 构造后只读。
     */
    struct ServerConfig
    {
        /// 服务端密码（连接构造时派生 16 字节 PSK）
        std::string password;
        /// 时间戳容忍窗口（秒）
        std::uint64_t TimeWindow{90};
    };

    // =========================================================================
    // 工具
    // =========================================================================

    /**
     * @brief 密码派生 16 字节 PSK（测试库约定：SHA256 前 16 字节）
     * @param password 密码
     * @return 16 字节 PSK
     */
    [[nodiscard]] inline auto DerivePsk(std::string_view password) -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 32> Hash{};
        unsigned int len = 0;
        EVP_Digest(password.data(), password.size(), Hash.data(), &len, EVP_sha256(), nullptr);
        std::array<std::uint8_t, 16> psk{};
        std::memcpy(psk.data(), Hash.data(), 16);
        return psk;
    }

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 salt 握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 客户端配置
     * @param Target 目标地址
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(SharedTransmission upstream, const ClientConfig &cfg,
                                      const ss::Address &Target)
        -> net::awaitable<std::pair<Error, SharedConn>>
    {
        auto c = cfg.UsePsk ? std::make_shared<Conn<>>(cfg.psk)
                                  : std::make_shared<Conn<>>(cfg.password);
        const auto err = co_await c->WriteHandshake(std::move(upstream), Target);
        SharedConn Conn;
        if (err == Error::none)
        {
            Conn = SharedConn(std::move(c));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::pair{err, std::move(Conn)};
    }

    /**
     * @brief 创建客户端 UDP 包连接（独立 UDP socket，不依赖 TCP）
     * @param ex 执行器
     * @param remote 代理服务器 UDP 端点（host:port）
     * @param cfg 客户端配置
     * @return 包连接（连接失败时为空）
     * @details 直接创建 UDP socket 连接服务器，逐包 AEAD 加密；
     * 无 TCP 握手（对齐 SIP022 独立数据报通道）。
     */
    [[nodiscard]] inline auto ConnectPacket(net::any_io_executor ex, const std::string &remote,
                                             const ClientConfig &cfg) -> SharedDgram
    {
        auto udp = std::make_shared<Preview::Transport::Unreliable>(ex);
        if (!udp->Connect(remote))
        {
            return nullptr;
        }
        const auto psk = cfg.UsePsk ? cfg.psk : DerivePsk(cfg.password);
        return std::make_shared<Dgram<>>(std::move(udp), psk);
    }

    /**
     * @brief 接收服务端流连接并完成首包握手
     * @param upstream 上游传输（所有权移交）
     * @param cfg 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const ServerConfig &cfg)
        -> net::awaitable<std::tuple<Error, ss::Message, SharedConn>>
    {
        auto c = std::make_shared<Conn<>>(cfg.password);
        auto [err, req] = co_await c->ReadHandshake(std::move(upstream));
        SharedConn Conn;
        if (err == Error::none)
        {
            Conn = SharedConn(std::move(c));
        }
        else
        {
            Conn = SharedConn{};
        }
        co_return std::tuple{err, std::move(req), std::move(Conn)};
    }

    /**
     * @brief 创建服务端 UDP 包连接（独立 UDP socket，不依赖 TCP）
     * @param ex 执行器
     * @param port 监听端口（0 = 系统分配）
     * @param cfg 服务端配置
     * @param bound 输出实际绑定端点（可为 nullptr）
     * @return 包连接（绑定失败时为空）
     * @details 绑定 UDP 端口监听，逐包 AEAD 加解密；无 TCP 握手。
     */
    [[nodiscard]] inline auto AcceptPacket(net::any_io_executor ex, unsigned short port,
                                            const ServerConfig &cfg,
                                            net::ip::udp::endpoint *bound = nullptr)
        -> SharedDgram
    {
        auto udp = std::make_shared<Preview::Transport::Unreliable>(ex);
        if (!udp->Bind(port))
        {
            return nullptr;
        }
        if (bound)
        {
            *bound = udp->LocalEndpoint();
        }
        return std::make_shared<Dgram<>>(std::move(udp), DerivePsk(cfg.password));
    }

    // 编解码类型 re-export（ss2022 命名空间 → shadowsocks2022）
    using Preview::Shadowsocks2022::Address;
    using Preview::Shadowsocks2022::AddressType;
    using Preview::Shadowsocks2022::Message;
    using Preview::Shadowsocks2022::Parser;
    using Preview::Shadowsocks2022::Serializer;

} // namespace Preview::Shadowsocks2022
