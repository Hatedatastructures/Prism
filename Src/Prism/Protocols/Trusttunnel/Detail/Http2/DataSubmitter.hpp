/**
 * @file DataSubmitter.hpp
 * @brief TrustTunnel H2 DATA 分块接纳与窗口背压 owner。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2/WireWriter.hpp>
#include <Prism/Protocols/Trusttunnel/Http2/Server/Types.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>

namespace Prism::Trusttunnel::Detail
{
    namespace Net = boost::asio;
    namespace H2 = Prism::Http2;

    struct Http2ServerDataRequest final
    {
        std::shared_ptr<H2::Session> Session;
        std::shared_ptr<Http2WireWriter> Wire;
        std::int32_t StreamId{0};
        std::span<const std::byte> Data;
    };

    struct Http2ServerDataWriter final
    {
        std::shared_ptr<H2::Session> Session;
        std::shared_ptr<Http2WireWriter> Wire;

        [[nodiscard]] auto operator()(
            const std::int32_t StreamId,
            const std::span<const std::byte> Data) const -> Net::awaitable<Http2ServerResult>;

        [[nodiscard]] static auto Run(Http2ServerDataRequest Value)
            -> Net::awaitable<Http2ServerResult>;
    };

    struct Http2ServerFinishRequest final
    {
        std::shared_ptr<H2::Session> Session;
        std::shared_ptr<Http2WireWriter> Wire;
        std::int32_t StreamId{0};
    };

    struct Http2ServerFinisher final
    {
        std::shared_ptr<H2::Session> Session;
        std::shared_ptr<Http2WireWriter> Wire;

        [[nodiscard]] auto operator()(const std::int32_t StreamId) const
            -> Net::awaitable<Http2ServerResult>;

        [[nodiscard]] static auto Run(Http2ServerFinishRequest Value)
            -> Net::awaitable<Http2ServerResult>;
    };
} // namespace Prism::Trusttunnel::Detail
