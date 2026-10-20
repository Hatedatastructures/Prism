/**
 * @file Anytls.hpp
 * @brief AnyTLS 配置与连接工厂公开接口。
 * @details 连接工厂接管输入传输；成功时调用者取得连接并负责半关闭与最终关闭，
 *          握手失败时协议 owner 负责取消、关闭并等待真实 Activity 退栈。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Anytls/Codec.hpp>
#include <Prism/Protocols/Anytls/Conn.hpp>
#include <Prism/Protocols/Anytls/Frame.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <string>

namespace Prism::Anytls
{

    /** @brief AnyTLS 客户端认证配置。 */
    struct ClientConfig
    {
        std::string Password;
    };

    /** @brief AnyTLS 服务端认证配置。 */
    struct ServerConfig
    {
        std::string Password;
    };

    /**
     * @brief 接管上游并完成 AnyTLS 客户端认证握手。
     * @return 成功时唯一协议连接；失败时保留 typed/native 首因。
     */
    [[nodiscard]] auto Connect(SharedTransmission Upstream, const ClientConfig& Config)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>;

    /**
     * @brief 接管上游并完成 AnyTLS 服务端认证校验。
     * @return 成功时唯一协议连接；失败时保留 typed/native 首因。
     */
    [[nodiscard]] auto Accept(SharedTransmission Upstream, const ServerConfig& Config)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>;

} // namespace Prism::Anytls
