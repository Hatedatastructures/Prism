/**
 * @file Types.hpp
 * @brief Native TLS façade 的 owning 输入与稳定结果类型。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <expected>
#include <functional>
#include <memory>
#include <string>

namespace Preview::Native
{
    namespace Net = boost::asio;

    /**
     * @brief 服务端 Native TLS 的 owning transport 与已协商元数据。
     * @details SNI 与 ECH 接受位来自握手完成后的 BoringSSL SSL 对象；成功接受 ECH 时，
     *          SNI 为解密后的 inner 值，未接受或 GREASE 时保留外层值。
     */
    struct NegotiatedTlsSession final
    {
        SharedTransmission Transport;
        std::string ServerName;
        std::string Alpn;
        std::string TlsVersion;
        bool EchAccepted{false};
    };

    using AcceptResult = std::expected<NegotiatedTlsSession, Preview::Fault::Failure>;
    using ConnectResult = std::expected<SharedTransmission, Preview::Fault::Failure>;

    /** @brief Native 服务端 TLS 握手的 owning 冷路径输入。 */
    struct AcceptRequest final
    {
        SharedTransmission Raw;
        std::reference_wrapper<Net::ssl::context> SslContext;
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
    };

    /** @brief Native 客户端 TLS 握手的 owning 冷路径输入。 */
    struct ConnectRequest final
    {
        SharedTransmission Raw;
        std::reference_wrapper<Net::ssl::context> SslContext;
        std::string ServerName;
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
    };
}
