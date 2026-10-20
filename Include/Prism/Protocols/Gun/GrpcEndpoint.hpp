/**
 * @file GrpcEndpoint.hpp
 * @brief Gun gRPC endpoint 的配置、metadata 与请求结果类型。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http2/Session.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Prism::Gun::Grpc
{
    namespace Net = boost::asio;
    namespace H2 = Prism::Http2;

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

    /**
     * @brief unary client 的响应、请求/读取终态及独立关闭收尾结果。
     * @details 完整响应可与 EOF/native 读取终态同时存在；不完整或协议错误响应不提供 Response。
     *          Run 完成时先 Close，再等待 Activity Drain；两种收尾失败分别保留，不覆盖响应或终态。
     */
    struct ClientOutcome final
    {
        /** @brief 完整 gRPC 响应；终态失败时仍可能保留已经完整解析的响应。 */
        std::optional<ClientResponse> Response;
        /** @brief 请求发送或响应读取中首先观察到的 typed terminal；干净完成时为 Success。 */
        Prism::Fault::Failure Terminal{};
        /** @brief wrapper Close 命令失败，与响应及读写终态独立。 */
        Prism::Fault::Failure CloseFailure{};
        /** @brief wrapper Activity Drain 失败，与 Close 命令结果独立。 */
        Prism::Fault::Failure DrainFailure{};
    };

    [[nodiscard]] auto MakeRequestHeaders(
        std::string_view Path,
        std::string_view Authority) -> H2::HeaderList;

    [[nodiscard]] auto ParseRequestHeaders(
        const H2::HeaderList &Headers) -> std::optional<RequestHeaders>;

    [[nodiscard]] auto MakeResponseHeaders() -> H2::HeaderList;

    [[nodiscard]] auto MakeResponseTrailers(std::uint32_t Status) -> H2::HeaderList;
}
