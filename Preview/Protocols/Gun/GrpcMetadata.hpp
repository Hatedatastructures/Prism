/**
 * @file GrpcMetadata.hpp
 * @brief gRPC 请求 metadata、响应 headers 和 trailers。
 */
#pragma once

#include <Preview/Protocols/Gun/GrpcTypes.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace Preview::Gun::Grpc
{

    [[nodiscard]] inline auto MakeRequestHeaders(std::string_view Path, std::string_view Authority)
        -> H2::HeaderList
    {
        return {{":method", "POST"}, {":scheme", "http"}, {":path", std::string(Path)},
            {":authority", std::string(Authority)}, {"content-type", "application/grpc"}, {"te", "trailers"}};
    }

    [[nodiscard]] inline auto ParseRequestHeaders(const H2::HeaderList& Headers)
        -> std::optional<RequestHeaders>
    {
        RequestHeaders Result;
        bool MethodOk = false;
        bool SchemeOk = false;
        for (const auto& Header : Headers)
        {
            if (Header.Name == ":method")
            {
                MethodOk = Header.Value == "POST";
            }
            else if (Header.Name == ":scheme")
            {
                SchemeOk = Header.Value == "http" || Header.Value == "https";
            }
            else if (Header.Name == ":path")
            {
                Result.Path = Header.Value;
            }
            else if (Header.Name == ":authority")
            {
                Result.Authority = Header.Value;
            }
            else if (Header.Name == "content-type")
            {
                Result.ContentType = Header.Value;
            }
            else if (Header.Name == "te")
            {
                Result.Te = Header.Value;
            }
        }
        if (!MethodOk || !SchemeOk || Result.Path.empty() || Result.Authority.empty() ||
            !std::string_view(Result.ContentType).starts_with("application/grpc") ||
            (!Result.Te.empty() && Result.Te != "trailers"))
        {
            return std::nullopt;
        }
        return Result;
    }

    [[nodiscard]] inline auto MakeResponseHeaders() -> H2::HeaderList
    {
        return {{":status", "200"}, {"content-type", "application/grpc"}, {"grpc-encoding", "identity"},
            {"grpc-accept-encoding", "identity"}};
    }

    [[nodiscard]] inline auto MakeResponseTrailers(const std::uint32_t Status) -> H2::HeaderList
    {
        return {{"grpc-status", std::to_string(Status)}, {"grpc-message", {}}};
    }

} // namespace Preview::Gun::Grpc
