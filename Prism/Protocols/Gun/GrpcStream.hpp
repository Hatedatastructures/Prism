/**
 * @file GrpcStream.hpp
 * @brief gRPC stream transport 的公开接收前门。
 * @details I/O driver、HTTP/2 session 与退役 ticket 由 Detail::StreamFactory
 *          唯一拥有；该前门返回唯一 Transmission owner。
 */
#pragma once

#include <Prism/Protocols/Gun/GrpcTypes.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcStreamFactory.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <utility>

namespace Prism::Gun::Grpc
{

    namespace Net = boost::asio;

    /**
     * @brief 接收 gRPC stream 并完成首个 request headers 握手。
     * @param Lower 按值移交的下层 Transmission；失败前门在其原 executor 退休资源。
     * @param ConfigValue 按值固定 path 与 message 上限。
     * @return 唯一拥有型 Transmission 或保留原生原因的 typed failure。
     * @details 成功后返回值拥有 stream driver；写半关闭只提交 trailers，最终关闭
     *          与 Activity drain 由返回的 Transmission owner 完成。
     */
    class StreamTransport final
    {
    public:
        [[nodiscard]] static auto Accept(
            Prism::SharedTransmission Lower,
            Config ConfigValue)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            co_return co_await Detail::StreamFactory::Accept(
                std::move(Lower), std::move(ConfigValue));
        }
    };

} // namespace Prism::Gun::Grpc