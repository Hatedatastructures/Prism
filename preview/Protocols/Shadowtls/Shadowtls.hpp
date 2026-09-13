/**
 * @file Shadowtls.hpp
 * @brief ShadowTLS v3 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectStandard / Accept / AcceptStandard
 *   ——认证握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（Types.hpp，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，SessionId HMAC 认证 + 数据透传）
 * - 编解码/认证：Codec.hpp（SessionId 生成/校验 + 帧 HMAC + KDF）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Shadowtls/Codec.hpp>
#include <preview/Protocols/Shadowtls/Conn.hpp>
#include <preview/Protocols/Shadowtls/Types.hpp>

namespace Preview::Shadowtls
{

    // =========================================================================
    // 参数（客户端与服务端装配参数）
    // =========================================================================

    /**
     * @struct ConnectParameters
     * @brief ShadowTLS 客户端连接装配参数
     * @details Upstream 的所有权转移给新连接；随机数视图和 Config 在握手期间借用。
     */
    struct ConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        std::span<const std::uint8_t> ServerRandom;
        std::span<const std::uint8_t> ClientRandom;
    };

    /**
     * @struct StandardConnectParameters
     * @brief 标准 TLS ClientHello 模板的客户端连接参数
     */
    struct StandardConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        std::span<const std::uint8_t> ClientHelloWire;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 SessionId 认证握手
     * @param Params 客户端连接装配参数
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(std::move(Params.Upstream), Params.Config.password);
        const auto Err = co_await Connection->WriteHandshake(Params.ServerRandom, Params.ClientRandom);
        SharedConn Result;
        if (Err == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Result = SharedConn{};
        }
        co_return std::pair{Err, std::move(Result)};
    }

    /**
     * @brief 使用真实 TLS 构造器提供的 ClientHello 完成 ShadowTLS SessionId 认证
     * @param Params 客户端连接参数
     * @return 错误码与协议连接
     * @note 只发送并认证 ClientHello，不驱动外层 TLS 状态机。
     */
    [[nodiscard]] inline auto ConnectStandard(StandardConnectParameters Params)
        -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(std::move(Params.Upstream), Params.Config.password);
        const auto Err = co_await Connection->WriteStandardHandshake(Params.ClientHelloWire);
        SharedConn Result;
        if (Err == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        co_return std::pair{Err, std::move(Result)};
    }

    /**
     * @brief 接收服务端流连接并完成 SessionId 认证校验
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config) -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream), Config.password);
        const auto Err = co_await Connection->ReadHandshake();
        SharedConn Result;
        if (Err == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Result = SharedConn{};
        }
        co_return std::pair{Err, std::move(Result)};
    }

    /**
     * @brief 接收并校验标准 TLS ClientHello
     * @param Upstream 底层传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、完整 ClientHello wire 与协议连接
     */
    [[nodiscard]] inline auto AcceptStandard(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::tuple<Error, std::vector<std::uint8_t>, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream), Config.password);
        const auto Err = co_await Connection->ReadStandardHandshake();
        std::vector<std::uint8_t> Wire;
        SharedConn Result;
        if (Err == Error::None)
        {
            Wire = Connection->TakeClientHelloWire();
            Result = SharedConn(std::move(Connection));
        }
        co_return std::tuple{Err, std::move(Wire), std::move(Result)};
    }

} // namespace Preview::Shadowtls

#include <preview/Protocols/Shadowtls/Server.hpp>
