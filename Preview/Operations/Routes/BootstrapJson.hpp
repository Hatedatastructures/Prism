/**
 * @file BootstrapJson.hpp
 * @brief Operations bootstrap 身份与一次性缓存策略的 JSON/HTTP 边界。
 */
#pragma once

#include <Preview/Operations/Routes/HttpJson.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Operations::HttpDetail
{

    /** @brief 已装配路由能力；数据可用性由每次查询返回的实时状态表达。 */
    inline constexpr std::array<std::string_view, 19> BootstrapCapabilities{
        "health.read",
        "metrics.read",
        "workers.read",
        "accounts.read",
        "accounts.revoke",
        "sessions.read",
        "sessions.cancel",
        "streams.read",
        "streams.reset",
        "tasks.read",
        "tasks.cancel",
        "generations.read",
        "events.read",
        "operations.status",
        "configuration.read",
        "configuration.reload.validate",
        "configuration.reload.apply",
        "workers.drain",
        "process.drain"};

    /** @brief 将启动期随机字节编码为小写十六进制文本。 */
    template <std::size_t Size>
    [[nodiscard]] inline auto EncodeHex(const std::array<std::uint8_t, Size> &Bytes)
        -> std::array<char, Size * 2U>
    {
        constexpr std::array<char, 16> Digits{
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        std::array<char, Size * 2U> Result{};
        for (std::size_t Index = 0; Index < Size; ++Index)
        {
            Result[Index * 2U] = Digits[Bytes[Index] >> 4U];
            Result[Index * 2U + 1U] = Digits[Bytes[Index] & 0x0fU];
        }
        return Result;
    }

    /** @brief 序列化真实进程身份和唯一启动期凭据；不写入日志或错误响应。 */
    [[nodiscard]] inline auto SerializeBootstrap(const BootstrapIdentity &Identity)
        -> std::optional<std::string>
    {
        const auto Incarnation = EncodeHex(Identity.ProcessIncarnation());
        const auto Token = EncodeHex(Identity.Token());
        JsonWriter Writer(1024U);
        if (!Writer.Append("{") || !Writer.Key("api_version") || !Writer.String("1") ||
            !Writer.Append(",") || !Writer.Key("process_id") ||
            !Writer.Decimal(Identity.Process().Value()) || !Writer.Append(",") ||
            !Writer.Key("process_incarnation") ||
            !Writer.String(std::string_view(Incarnation.data(), Incarnation.size())) ||
            !Writer.Append(",") || !Writer.Key("command_token") ||
            !Writer.String(std::string_view(Token.data(), Token.size())) ||
            !Writer.Append(",") || !Writer.Key("capabilities") || !Writer.Append("["))
        {
            return std::nullopt;
        }
        bool FirstCapability = true;
        for (const auto Capability : BootstrapCapabilities)
        {
            if ((!FirstCapability && !Writer.Append(",")) || !Writer.String(Capability))
            {
                return std::nullopt;
            }
            FirstCapability = false;
        }
        if (!Writer.Append("]") || !Writer.Append("}") || !Writer.Good())
        {
            return std::nullopt;
        }
        return std::move(Writer).Take();
    }

    /** @brief 对包含命令凭据的成功 Bootstrap 响应禁止缓存。 */
    [[nodiscard]] inline auto MakeNoStoreResponse(const int Status, std::string Body)
        -> std::string
    {
        auto Result = MakeResponse(Status, std::move(Body));
        const auto HeaderEnd = Result.find("\r\n\r\n");
        if (HeaderEnd != std::string::npos)
        {
            Result.insert(HeaderEnd + 2U, "Cache-Control: no-store\r\n");
        }
        return Result;
    }

} // namespace Preview::Operations::HttpDetail
