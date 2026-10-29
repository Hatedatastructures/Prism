/**
 * @file Options.hpp
 * @brief Shadowsocks 2022 连接构造配置。
 * @details 由连接入口和会话 owner 共同消费；配置的 executor 在握手绑定 upstream
 *          前提供有效执行域，之后会话跟随 upstream 的 executor。
 */
#pragma once

#include <Prism/Account/Authenticator.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <array>
#include <cstdint>

namespace Prism::Shadowsocks2022
{

    struct ConnOptions final
    {
        boost::asio::any_io_executor Executor;
        std::array<std::uint8_t, 16> Psk{};
        std::uint64_t TimeWindow{90};
        Prism::SharedAuthenticator AuthenticatorOwner;
    };

} // namespace Prism::Shadowsocks2022
