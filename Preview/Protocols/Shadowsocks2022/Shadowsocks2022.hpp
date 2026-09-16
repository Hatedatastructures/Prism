/**
 * @file Shadowsocks2022.hpp
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
#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Utility/Crypto/Base64.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Transport/Unreliable.hpp>
#include <Preview/Protocols/Shadowsocks2022/Conn.hpp>
#include <Preview/Protocols/Shadowsocks2022/Dgram.hpp>
#include <Preview/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief SS2022 客户端配置
     * @details 控制客户端的行为：Base64 编码的 16 字节 PSK，或显式原始 PSK。
     */
    struct ClientConfig
    {
        /// 客户端 PSK（Base64 编码；显式 Psk 优先）
        std::string password;
        /// 直接指定 16 字节 PSK（标准配置：base64 psk 解码后原始字节，优先于 password）
        bool UsePsk{false};
        std::array<std::uint8_t, 16> Psk{};
    };

    /**
     * @struct ServerConfig
     * @brief SS2022 服务端配置
     * @details 控制服务端的行为：Base64 编码的 16 字节 PSK，或显式原始 PSK，
     *          时间戳窗口和独立 UDP 数据报开关。
     * 构造后只读。
     */
    struct ServerConfig
    {
        /// 服务端 PSK（Base64 编码；显式 Psk 优先）
        std::string password;
        /// 直接指定 16 字节 PSK（标准 UDP 配置，优先于 password）
        bool UsePsk{false};
        std::array<std::uint8_t, 16> Psk{};
        /// 时间戳容忍窗口（秒）
        std::uint64_t TimeWindow{90};
        /// 认证器（运行时按 typed PSK 校验）
        const Preview::Authenticator *Authenticator{nullptr};
        /// 认证器共享所有权
        Preview::SharedAuthenticator AuthenticatorOwner{};
        /// 是否允许独立 UDP 数据报通道
        bool EnableUdp{true};

        [[nodiscard]] auto ResolveAuthenticator() const noexcept
            -> const Preview::Authenticator *
        {
            if (AuthenticatorOwner)
            {
                return AuthenticatorOwner.get();
            }
            return Authenticator;
        }
    };

    /**
     * @struct AcceptPacketParameters
     * @brief Shadowsocks 2022 服务端 UDP 装配参数
     * @details Executor 与端口按值传递；Config 借用；Bound 由调用方拥有，
     * 仅在绑定成功时写入实际端点。
     */
    struct AcceptPacketParameters
    {
        Net::any_io_executor Executor;
        unsigned short Port;
        const ServerConfig &Config;
        Net::ip::udp::endpoint *Bound{nullptr};
    };

    // =========================================================================
    // 工具
    // =========================================================================

    /**
     * @brief 解码配置中的 16 字节 PSK
     * @param Password Base64 编码的原始 PSK
     * @return 长度正确时返回 PSK，否则返回空
     */
    [[nodiscard]] inline auto DecodePsk(std::string_view Password)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        const auto Decoded = Preview::Crypto::Base64Decode(Password);
        if (Decoded.size() != 16)
        {
            return std::nullopt;
        }
        std::array<std::uint8_t, 16> Psk{};
        std::memcpy(Psk.data(), Decoded.data(), Psk.size());
        return Psk;
    }

    /**
     * @brief 按配置选择原始 PSK 或 Base64 密码派生 PSK
     * @param UsePsk 是否使用 RawPsk
     * @param RawPsk 原始 16 字节 PSK
     * @param Password Base64 编码密码
     * @return 有效 PSK，否则返回空
     */
    [[nodiscard]] inline auto ResolvePsk(
        bool UsePsk,
        const std::array<std::uint8_t, 16> &RawPsk,
        std::string_view Password) -> std::optional<std::array<std::uint8_t, 16>>
    {
        if (UsePsk)
        {
            return RawPsk;
        }
        return DecodePsk(Password);
    }

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 salt 握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @param Target 目标地址
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target) -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        std::shared_ptr<Conn<>> Connection;
        if (Config.UsePsk)
        {
            Connection = std::make_shared<Conn<>>(Config.Psk);
        }
        else
        {
            Connection = std::make_shared<Conn<>>(Config.password);
        }
        const auto ErrorCode = co_await Connection->WriteHandshake(std::move(Upstream), Target);
        SharedConn Result;
        if (ErrorCode == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Connection->Close();
        }
        co_return std::pair{ErrorCode, std::move(Result)};
    }

    /**
     * @brief 创建客户端 UDP 包连接（独立 UDP socket，不依赖 TCP）
     * @param Executor 执行器
     * @param Remote 代理服务器 UDP 端点（host:port）
     * @param Config 客户端配置
     * @return 包连接（连接失败时为空）
     * @details 直接创建 UDP socket 连接服务器，逐包 AEAD 加密；
     * 无 TCP 握手（对齐 SIP022 独立数据报通道）。
     */
    [[nodiscard]] inline auto ConnectPacket(
        Net::any_io_executor Executor,
        const std::string &Remote,
        const ClientConfig &Config) -> SharedDgram
    {
        auto Udp = std::make_shared<Preview::Transport::Unreliable>(Executor);
        if (!Udp->Connect(Remote))
        {
            Udp->Close();
            return nullptr;
        }
        const auto Psk = ResolvePsk(Config.UsePsk, Config.Psk, Config.password);
        if (!Psk)
        {
            Udp->Close();
            return nullptr;
        }
        return std::make_shared<Dgram<>>(std::move(Udp), *Psk, UdpRole::Client);
    }

    /**
     * @brief 接收服务端流连接并完成首包握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config) -> Net::awaitable<std::tuple<Error, Message, SharedConn>>
    {
        std::shared_ptr<Conn<>> Connection;
        if (Config.UsePsk)
        {
            Connection = std::make_shared<Conn<>>(Config.Psk,
                                                  Config.TimeWindow,
                                                  Config.ResolveAuthenticator(),
                                                  Config.AuthenticatorOwner);
        }
        else
        {
            Connection = std::make_shared<Conn<>>(Config.password,
                                                  Config.TimeWindow,
                                                  Config.ResolveAuthenticator(),
                                                  Config.AuthenticatorOwner);
        }
        auto [ErrorCode, Request] = co_await Connection->ReadHandshake(std::move(Upstream));
        SharedConn Result;
        if (ErrorCode == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Connection->Close();
        }
        co_return std::tuple{ErrorCode, std::move(Request), std::move(Result)};
    }

    /**
     * @brief 创建服务端 UDP 包连接（独立 UDP socket，不依赖 TCP）
     * @param Params 服务端 UDP 装配参数
     * @return 包连接（绑定失败时为空）
     * @details 绑定 UDP 端口监听，逐包 AEAD 加解密；无 TCP 握手。
     */
    [[nodiscard]] inline auto AcceptPacket(AcceptPacketParameters Params) -> SharedDgram
    {
        if (!Params.Config.EnableUdp)
        {
            return nullptr;
        }
        auto Udp = std::make_shared<Preview::Transport::Unreliable>(Params.Executor);
        if (!Udp->Bind(Params.Port))
        {
            Udp->Close();
            return nullptr;
        }
        // 独立 UDP 服务端必须按每个已认证数据报的来源回包，不能把
        // Unreliable 的首次来源捕获为全局共享远端。
        Udp->AllowAnyPeer();
        const auto Psk = ResolvePsk(
            Params.Config.UsePsk,
            Params.Config.Psk,
            Params.Config.password);
        if (!Psk)
        {
            Udp->Close();
            return nullptr;
        }
        if (Params.Bound)
        {
            *Params.Bound = Udp->LocalEndpoint();
        }
        return std::make_shared<Dgram<>>(std::move(Udp), *Psk, UdpRole::Server);
    }

    /**
     * @brief 使用临时端口创建服务端 UDP 包连接
     * @param Executor 执行器
     * @param Port 监听端口（0 = 系统分配）
     * @param Config 服务端配置（借用）
     * @return 包连接（绑定失败时为空）
     */
    [[nodiscard]] inline auto AcceptPacket(
        Net::any_io_executor Executor,
        unsigned short Port,
        const ServerConfig &Config) -> SharedDgram
    {
        return AcceptPacket(AcceptPacketParameters{Executor, Port, Config});
    }

    // 编解码类型 re-export（Codec.hpp 定义，供外部以本命名空间直接引用）
    using Preview::Shadowsocks2022::Address;
    using Preview::Shadowsocks2022::AddressType;
    using Preview::Shadowsocks2022::Message;
    using Preview::Shadowsocks2022::Parser;
    using Preview::Shadowsocks2022::Serializer;

} // namespace Preview::Shadowsocks2022
