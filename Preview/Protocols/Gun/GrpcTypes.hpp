/**
 * @file GrpcTypes.hpp
 * @brief gRPC endpoint 的配置、请求结果和回调类型。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Http2/Session.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace Preview::Gun::Grpc
{

    namespace Net = boost::asio;
    namespace H2 = Preview::Http2;

    inline constexpr std::size_t DefaultMaxMessageBytes = 16U * 1024U * 1024U;

    struct Config final
    {
        std::string Path{"/GunService/Tun"};
        std::string Authority{"gun"};
        std::size_t MaxMessageBytes{DefaultMaxMessageBytes};
    };

    struct RequestHeaders final
    {
        std::string Path;
        std::string Authority;
        std::string ContentType;
        std::string Te;
    };

    using MessageHandler = std::function<std::vector<std::byte>(std::span<const std::byte>)>;

    struct ClientResponse final
    {
        std::uint32_t GrpcStatus{1};
        H2::HeaderList ResponseHeaders;
        H2::HeaderList Trailers;
        std::vector<std::byte> Payload;
    };

    using ClientResult = std::expected<ClientResponse, Preview::Fault::Failure>;

} // namespace Preview::Gun::Grpc
