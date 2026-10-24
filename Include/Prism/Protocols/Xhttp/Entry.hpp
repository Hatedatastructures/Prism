/**
 * @file Entry.hpp
 * @brief XHTTP 客户端与服务端连接工厂接口。
 * @details factory 接管 raw transport 与 byte pool；TLS context 由调用者保活至 awaitable 完成。
 */
#pragma once

#include <Prism/Protocols/Xhttp/ConnectionTypes.hpp>

#include <boost/asio/awaitable.hpp>

#include <memory>

namespace Prism::Xhttp
{
    struct AcceptRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        Config Configuration;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    [[nodiscard]] auto Connect(ClientConnectRequest Request)
        -> Net::awaitable<FactoryResult>;

    [[nodiscard]] auto Accept(AcceptRequest Request)
        -> Net::awaitable<ServerAcceptResult>;
}
