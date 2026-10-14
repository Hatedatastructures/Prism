/**
 * @file Restls.hpp
 * @brief Restls 协议的稳定客户端工厂与 server-session façade。
 * @details 根目录保留配置、typed 工厂和 ServerSession；record、认证、连接与 relay 状态由本协议 Detail owner 实现。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <tuple>
#include <utility>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Restls/Detail/Record.hpp>
#include <Preview/Protocols/Restls/Detail/Session.hpp>
#include <Preview/Protocols/Restls/Detail/Control.hpp>
#include <Preview/Protocols/Restls/Server.hpp>
#include <Preview/Protocols/Restls/Types.hpp>

namespace Preview::Restls
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief Restls 客户端配置
     * @details 控制客户端的行为：认证密码。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端认证密码（字段名称保持现有配置兼容）
        std::string password;
    };

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成认证握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @param ServerRandom 服务端随机数（32 字节）
     * @return 成功时为唯一连接 owner；失败时保留协议分类与底层 cause
     */
    [[nodiscard]] inline auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        std::span<const std::uint8_t> ServerRandom)
        -> Net::awaitable<Result<SharedConn>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(ProtocolFailure(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(std::move(Upstream), Config.password);
        const auto Handshake = co_await Connection->WriteHandshake(ServerRandom);
        if (!Handshake)
        {
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(std::move(Connection));
            const auto CleanupFailure = Retired
                                            ? Failure{}
                                            : Detail::WireFailure(Retired.error());
            co_return std::unexpected(
                PreserveFirstFailure(Handshake.error(), CleanupFailure));
        }
        co_return SharedConn(std::move(Connection));
    }

    /**
     * @brief 接收服务端流连接并完成认证握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @param ServerRandom 服务端随机数（32 字节）
     * @return 成功时为唯一连接 owner；失败时保留协议分类与底层 cause
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config,
        std::span<const std::uint8_t> ServerRandom)
        -> Net::awaitable<Result<SharedConn>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(ProtocolFailure(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(std::move(Upstream), Config.password);
        const auto Handshake = co_await Connection->ReadHandshake(ServerRandom);
        if (!Handshake)
        {
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(std::move(Connection));
            const auto CleanupFailure = Retired
                                            ? Failure{}
                                            : Detail::WireFailure(Retired.error());
            co_return std::unexpected(
                PreserveFirstFailure(Handshake.error(), CleanupFailure));
        }
        co_return SharedConn(std::move(Connection));
    }

} // namespace Preview::Restls
