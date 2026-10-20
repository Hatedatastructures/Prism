/**
 * @file Tls.hpp
 * @brief Native 严格 TLS 握手的私有执行 owner。
 * @details 负责准入、TLS engine 调用、失败退休与成功 transport 接管。
 */
#pragma once

#include <Prism/Protocols/Native/Native.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <functional>
#include <memory>
#include <string>

namespace Prism::Native
{
    namespace Detail
    {
        struct StrictHandshakeRequest final
        {
            SharedTransmission Inbound;
            std::reference_wrapper<Net::ssl::context> Context;
            std::string ServerName;
            std::shared_ptr<Prism::Memory::BytePool> Bytes;
            Prism::Transport::Encrypted::HandshakeRole Role{
                Prism::Transport::Encrypted::HandshakeRole::Server};
        };

        [[nodiscard]] auto RunStrictHandshake(StrictHandshakeRequest Request)
            -> Net::awaitable<AcceptResult>;
    }
}
