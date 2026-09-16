/**
 * @file Anytls.hpp
 * @brief AnyTLS 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / Accept ——认证握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，认证帧 + 数据透传）
 * - 编解码/认证：Codec.hpp（密码哈希 + 认证帧编解码）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Anytls/Codec.hpp>
#include <Preview/Protocols/Anytls/Conn.hpp>
#include <Preview/Protocols/Anytls/Types.hpp>

namespace Preview::Anytls
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief AnyTLS 客户端配置
     * @details 控制客户端的行为：认证密码。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端认证密码
        std::string Password;
    };

    /**
     * @struct ServerConfig
     * @brief AnyTLS 服务端配置
     * @details 控制服务端的行为：认证密码。构造后只读。
     */
    struct ServerConfig
    {
        /// 服务端认证密码
        std::string Password;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成认证握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config) -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream), Config.Password);
        const auto ErrorCode = co_await Connection->WriteHandshake();
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
     * @brief 接收服务端流连接并完成认证校验
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config) -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream), Config.Password);
        const auto ErrorCode = co_await Connection->ReadHandshake();
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

} // namespace Preview::Anytls
