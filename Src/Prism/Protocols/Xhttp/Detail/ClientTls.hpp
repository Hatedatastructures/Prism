/**
 * @file ClientTls.hpp
 * @brief XHTTP 客户端 TLS 握手与失败回收策略。
 */

#pragma once

#include <Prism/Protocols/Xhttp/Detail/CarrierSessionSupport.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Encrypted.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl.hpp>

#include <expected>
#include <memory>
#include <string>

namespace Prism::Xhttp::Detail
{

    /** @brief XHTTP 客户端 TLS 建立的完整冷路径输入。 */
    struct ClientTlsRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        std::string Host;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    /** @brief 将 TLS engine 加入已预预约的失败退休票据并等待真实关闭。 */
    [[nodiscard]] auto RetireClientTlsFailure(
        Prism::Contract::InboundAdmission &Admission,
        Prism::Transport::Encrypted::SharedStream Stream,
        Prism::Fault::Failure Cause) -> Net::awaitable<Prism::Fault::Failure>;

    /** @brief 建立客户端 TLS 流并应用 SNI、ALPN 和超时回收策略。 */
    [[nodiscard]] auto ConnectTls(
        ClientTlsRequest Request,
        Prism::Contract::InboundAdmission &Admission)
        -> Net::awaitable<std::expected<Prism::Transport::Encrypted::SharedStream,
                                        Prism::Fault::Failure>>;

} // namespace Prism::Xhttp::Detail
