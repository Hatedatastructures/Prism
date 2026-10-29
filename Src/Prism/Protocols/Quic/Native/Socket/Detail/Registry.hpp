/**
 * @file Registry.hpp
 * @brief 原生 QUIC connection 的 UDP socket 独占登记契约。
 */
#pragma once

#include <boost/asio/ip/udp.hpp>

#include <memory>

namespace Prism::Quic::Detail
{
    struct SocketToken final
    {
    };

    /** @brief 为连接登记独占 socket；重复登记同一 socket 返回空 token。 */
    [[nodiscard]] auto AcquireSocketToken(
        const std::shared_ptr<boost::asio::ip::udp::socket> &Socket)
        -> std::shared_ptr<SocketToken>;

    /** @brief 释放由对应连接持有的 socket 登记。 */
    auto ReleaseSocketToken(
        const std::shared_ptr<boost::asio::ip::udp::socket> &Socket,
        const std::shared_ptr<SocketToken> &Token) -> void;
} // namespace Prism::Quic::Detail
