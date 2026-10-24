/** @file TransferRequestKey.hpp
 * @brief 为持久流量预约无歧义编码预算owner与进程账本身份。
 */
#pragma once

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace Prism::Account::Detail
{
    /** @brief 一次持久流量预约请求的命名空间、稳定身份与递增序号。 */
    struct TransferRequestIdentity final
    {
        std::uint64_t Namespace{0};
        std::string_view Incarnation;
        std::string_view AccountKey;
        std::uint64_t Sequence{0};
    };

    /** @brief 使用栈缓冲格式化无符号字段。 */
    [[nodiscard]] inline auto AppendRequestKeyNumber(std::string& Output,
        const std::uint64_t Value) -> bool
    {
        std::array<char, 20> Buffer{};
        const auto Converted = std::to_chars(Buffer.data(), Buffer.data() + Buffer.size(), Value);
        if (Converted.ec != std::errc{}) return false;
        Output.append(Buffer.data(), static_cast<std::size_t>(Converted.ptr - Buffer.data()));
        return true;
    }

    /** @brief 长度前缀使任意身份字符串组合保持唯一。 */
    [[nodiscard]] inline auto MakeTransferRequestKey(
        const TransferRequestIdentity& Identity) -> std::optional<std::string>
    {
        std::string Result{"budget:"};
        if (!AppendRequestKeyNumber(Result, Identity.Namespace)) return std::nullopt;
        Result.push_back(':');
        if (!AppendRequestKeyNumber(Result,
            static_cast<std::uint64_t>(Identity.Incarnation.size())))
            return std::nullopt;
        Result.push_back(':');
        if (!Identity.Incarnation.empty())
            Result.append(Identity.Incarnation.data(), Identity.Incarnation.size());
        Result.push_back(':');
        if (!AppendRequestKeyNumber(Result,
            static_cast<std::uint64_t>(Identity.AccountKey.size())))
            return std::nullopt;
        Result.push_back(':');
        if (!Identity.AccountKey.empty())
            Result.append(Identity.AccountKey.data(), Identity.AccountKey.size());
        Result.push_back(':');
        if (!AppendRequestKeyNumber(Result, Identity.Sequence)) return std::nullopt;
        return Result;
    }
}
