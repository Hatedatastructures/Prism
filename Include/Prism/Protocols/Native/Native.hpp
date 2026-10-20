/**
 * @file Native.hpp
 * @brief Native TLS carrier 的公开请求、结果与握手入口。
 * @details TLS handshake 状态由协议私有 owner 管理；调用方按值移交 transport，
 *          并在 awaitable 完成前保活借用的 SSL context。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <expected>
#include <functional>
#include <memory>
#include <string>

namespace Prism::Native
{
    namespace Net = boost::asio;

    /** @brief TLS 握手完成后的 owning transport 与协商元数据。 */
    struct NegotiatedTlsSession final
    {
        SharedTransmission Transport;
        std::string ServerName;
        std::string Alpn;
        std::string TlsVersion;
        bool EchAccepted{false};
    };

    using AcceptResult = std::expected<NegotiatedTlsSession, Prism::Fault::Failure>;
    using ConnectResult = std::expected<SharedTransmission, Prism::Fault::Failure>;

    /** @brief Native 服务端 TLS 握手的 owning 冷路径输入。 */
    struct AcceptRequest final
    {
        SharedTransmission Raw;
        std::reference_wrapper<Net::ssl::context> SslContext;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    /** @brief Native 客户端 TLS 握手的 owning 冷路径输入。 */
    struct ConnectRequest final
    {
        SharedTransmission Raw;
        std::reference_wrapper<Net::ssl::context> SslContext;
        std::string ServerName;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    /**
     * @brief 严格完成服务端 TLS 握手。
     * @param Request 入站载体、借用的 SSL context 与有界传输池。
     * @return owning transport 与协商元数据，失败保留完整 Fault。
     */
    [[nodiscard]] auto Accept(AcceptRequest Request) -> Net::awaitable<AcceptResult>;

    /** @brief 严格完成客户端 TLS 握手并返回 owning TLS transport。 */
    [[nodiscard]] auto Connect(ConnectRequest Request) -> Net::awaitable<ConnectResult>;
}
