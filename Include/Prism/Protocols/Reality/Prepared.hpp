/**
 * @file Prepared.hpp
 * @brief Reality 唯一已预读 ClientHello 的 typed 服务端握手接口。
 */
#pragma once

#include <Prism/Protocols/Reality/CarrierTypes.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>

namespace Prism::Reality
{
    [[nodiscard]] auto AcceptPrepared(PreparedRequest Request)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>;
}
