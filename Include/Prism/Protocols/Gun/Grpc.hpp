/**
 * @file Grpc.hpp
 * @brief Gun gRPC stream endpoint 与 wire framing 入口。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Gun/GrpcEndpoint.hpp>
#include <Prism/Protocols/Gun/GrpcFraming.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>

namespace Prism::Gun::Grpc
{
    /**
     * @brief 接收 gRPC stream 并完成首个 request headers 握手。
     * @details Lower 按值移交；成功后返回值拥有 stream driver。最终关闭由返回的
     *          Transmission owner 完成，失败保留原生原因。
     */
    class StreamTransport final
    {
    public:
        [[nodiscard]] static auto Accept(
            Prism::SharedTransmission Lower,
            Config ConfigValue)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>;
    };
}
