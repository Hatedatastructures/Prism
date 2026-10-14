/**
 * @file Conn.hpp
 * @brief Native 严格 TLS 客户端与服务端 typed 握手 façade。
 * @details 唯一 public 入口将 owning request 交给协议私有 TLS owner。
 */
#pragma once

#include <Preview/Protocols/Native/Types.hpp>
#include <Preview/Protocols/Native/Detail/Tls.hpp>

#include <boost/asio/awaitable.hpp>

#include <utility>

namespace Preview::Native
{    /**
     * @brief 严格完成服务端 TLS 握手。
     * @param Raw 入站载体，所有权移交至返回的传输或 admission ticket。
     * @param SslContext 必须保活至握手协程返回的服务端 TLS context。
     * @param Bytes 与入站 worker 同代的有界传输池。
     * @return owning 传输及 BoringSSL 实际协商的 SNI、ALPN、TLS 版本和 ECH 接受位；失败保留完整 Fault。
     */
    [[nodiscard]] inline auto Accept(AcceptRequest Request) -> Net::awaitable<AcceptResult>
    {
        co_return co_await Detail::RunStrictHandshake(Detail::StrictHandshakeRequest{
            std::move(Request.Raw), Request.SslContext, {}, std::move(Request.Bytes),
            Preview::Transport::Encrypted::HandshakeRole::Server});
    }

    /**
     * @brief 严格完成客户端 TLS 握手。
     * @param Request 入站载体、借用的 SSL context、SNI 与有界池的 owning request。
     * @return owning TLS 传输；客户端连接维持原有结果形状并保留完整 Fault。
     */
    [[nodiscard]] inline auto Connect(ConnectRequest Request) -> Net::awaitable<ConnectResult>
    {
        auto Result = co_await Detail::RunStrictHandshake(Detail::StrictHandshakeRequest{
            std::move(Request.Raw), Request.SslContext, std::move(Request.ServerName),
            std::move(Request.Bytes), Preview::Transport::Encrypted::HandshakeRole::Client});
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        co_return std::move(Result->Transport);
    }
}
