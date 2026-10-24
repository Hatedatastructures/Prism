/**
 * @file SingMux.hpp
 * @brief sing-mux 会话协商、虚拟流请求与服务端响应契约。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

#include <Prism/Foundation/Fault/Failure.hpp>
#include "Codec.hpp"
#include <Prism/Protocols/Mux/SingMux/Types.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Mux::Detail::SingMux
{

    namespace Net = boost::asio;

    /** @brief 单个完整协议字段及与它同次到达的终态。 */
    struct ExactFieldReadResult final
    {
        std::optional<Prism::Fault::Failure> Terminal;
    };

    /** @brief 已解析的完整会话请求及最后必需字段后的同次终态。 */
    struct SessionRequestReadResult final
    {
        Prism::Mux::SingMux::SessionRequest Request;
        std::optional<Prism::Fault::Failure> Terminal;
    };

    namespace SessionDetail
    {
        /** @brief 精确读取完整协议字段，并保留其后的同次终态。 */
        [[nodiscard]] auto ReadExactField(
            const Prism::SharedTransmission &Raw,
            std::span<std::uint8_t> Buffer)
            -> Net::awaitable<std::expected<ExactFieldReadResult, Prism::Fault::Failure>>;
    }

    /** @brief 完整 stream request 及最后必需字段之后同次到达的终态。 */
    struct StreamRequestReadResult final
    {
        StreamRequest Request;
        std::optional<Prism::Fault::Failure> Terminal;
    };

    [[nodiscard]] auto MakeSessionRequest(
        const std::array<std::uint8_t, 2> &Prefix,
        bool Padding,
        std::optional<Prism::Fault::Failure> Terminal)
        -> std::expected<SessionRequestReadResult, Prism::Fault::Failure>;

    [[nodiscard]] auto ReadSessionRequest(Prism::SharedTransmission Raw)
        -> Net::awaitable<std::expected<SessionRequestReadResult, Prism::Fault::Failure>>;

    [[nodiscard]] auto ReadStreamRequest(Prism::SharedTransmission Raw)
        -> Net::awaitable<std::expected<StreamRequestReadResult, Prism::Fault::Failure>>;

} // namespace Prism::Mux::Detail::SingMux
