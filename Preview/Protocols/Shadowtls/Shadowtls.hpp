/**
 * @file Shadowtls.hpp
 * @brief ShadowTLS v3 稳定 typed 工厂与 server-session façade。
 * @details 根目录保留配置与连接工厂；SessionId、record、control 和 relay 状态由本协议 Detail owner 实现。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <expected>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Shadowtls/Detail/Record.hpp>
#include <Preview/Protocols/Shadowtls/Detail/Session.hpp>
#include <Preview/Protocols/Shadowtls/Detail/Control.hpp>
#include <Preview/Protocols/Shadowtls/Types.hpp>

namespace Preview::Shadowtls
{

    /** @brief 标准服务端握手完成后交付的 wire 与协议连接。 */
    struct ServerHandover final
    {
        std::vector<std::uint8_t> ClientHelloWire;
        SharedConn Connection;
    };

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
     * @brief 标准 TLS ClientHello 模板的客户端连接参数。
     * @details Upstream 所有权移交给结果连接；Config 与 ClientHelloWire 借用至协程返回。
     */
    struct StandardConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        std::span<const std::uint8_t> ClientHelloWire;
    };

    // =========================================================================
    /** @brief 标准 ClientHello 发出后的拥有 wire 与传输结果。
     * @details ClientHelloWire 是协议捕获的独立字节副本；Connection 遵循 Transmission 读写与关闭合同。
     */
    struct StandardConnectResult final
    {
        std::vector<std::uint8_t> ClientHelloWire;
        SharedConn Connection;
    };

    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 SessionId 认证握手
     * @param Params 客户端连接装配参数
     * @return 唯一 typed 连接结果；失败保留 Fault、Native 和已发送字节数。
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> Net::awaitable<Result<SharedConn>>
    {
        if (!Params.Upstream)
        {
            co_return std::unexpected(FailureFromError(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(std::move(Params.Upstream), Params.Config.Password);
        auto Handshake = co_await Connection->WriteHandshake(Params.ServerRandom, Params.ClientRandom);
        if (!Handshake)
        {
            auto Failure = Handshake.error();
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(
                std::static_pointer_cast<Preview::Transmission>(std::move(Connection)));
            if (!Retired && !Failure.Native) Failure.Native = Retired.error().Native;
            co_return std::unexpected(std::move(Failure));
        }
        co_return SharedConn(std::move(Connection));
    }

    /**
     * @brief 使用真实 TLS 构造器提供的 ClientHello 完成 ShadowTLS SessionId 认证。
     * @param Params 入站传输及借用配置与 ClientHello 的 owning request。
     * @return 拥有 ClientHello 副本和传输句柄的 typed 结果；失败保留 Fault、Native 与已发送字节数。
     * @note 不驱动外层 TLS 状态机；成功后传输由调用者按 Transmission 合同关闭。
     */
    [[nodiscard]] inline auto ConnectStandard(StandardConnectParameters Params)
        -> Net::awaitable<Result<StandardConnectResult>>
    {
        if (!Params.Upstream)
        {
            co_return std::unexpected(FailureFromError(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(std::move(Params.Upstream), Params.Config.Password);
        auto Handshake = co_await Connection->WriteStandardHandshake(Params.ClientHelloWire);
        if (!Handshake)
        {
            auto Failure = Handshake.error();
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(
                std::static_pointer_cast<Preview::Transmission>(std::move(Connection)));
            if (!Retired && !Failure.Native) Failure.Native = Retired.error().Native;
            co_return std::unexpected(std::move(Failure));
        }
        co_return StandardConnectResult{Connection->TakeClientHelloWire(), SharedConn(std::move(Connection))};
    }

    /**
     * @brief 接收服务端流连接并完成 SessionId 认证校验
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 唯一 typed 连接结果；失败保留 Fault、Native 和已读取字节数。
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config) -> Net::awaitable<Result<SharedConn>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(FailureFromError(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(std::move(Upstream), Config.Password);
        auto Handshake = co_await Connection->ReadHandshake();
        if (!Handshake)
        {
            auto Failure = Handshake.error();
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(
                std::static_pointer_cast<Preview::Transmission>(std::move(Connection)));
            if (!Retired && !Failure.Native) Failure.Native = Retired.error().Native;
            co_return std::unexpected(std::move(Failure));
        }
        co_return SharedConn(std::move(Connection));
    }

    /**
     * @brief 接收并校验标准 TLS ClientHello
     * @param Upstream 底层传输（所有权移交）
     * @param Config 服务端配置
     * @return 唯一 typed handover；失败保留 Fault、Native 与读取进度。
     */
    [[nodiscard]] inline auto AcceptStandard(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<Result<ServerHandover>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(FailureFromError(Error::NotOpen));
        }
        auto Connection = std::make_shared<Detail::Conn<>>(std::move(Upstream), Config.Password);
        auto Handshake = co_await Connection->ReadStandardHandshake();
        if (!Handshake)
        {
            auto Failure = Handshake.error();
            const auto Retired = co_await Detail::TransportRetirement::RetireAndDrain(
                std::static_pointer_cast<Preview::Transmission>(std::move(Connection)));
            if (!Retired && !Failure.Native) Failure.Native = Retired.error().Native;
            co_return std::unexpected(std::move(Failure));
        }
        co_return ServerHandover{Connection->TakeClientHelloWire(), SharedConn(std::move(Connection))};
    }

} // namespace Preview::Shadowtls

#include <Preview/Protocols/Shadowtls/Server.hpp>
