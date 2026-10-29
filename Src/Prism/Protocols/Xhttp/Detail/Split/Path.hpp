/**
 * @file Path.hpp
 * @brief XHTTP Stream-up 与 Packet-up 路径编码及解析。
 */

#pragma once

#include <Prism/Protocols/Xhttp/Detail/CarrierSessionSupport.hpp>

#include <atomic>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace Prism::Xhttp::Detail
{

    struct SplitPath final
    {
        std::string Session;
        std::uint64_t Sequence{0};
        bool HasSequence{false};
    };

    [[nodiscard]] inline auto MakeSplitPath(
        std::string_view Base,
        std::string_view Session,
        const std::optional<std::uint64_t> Sequence = std::nullopt) -> std::string
    {
        std::string Result(Base);
        if (Base == "/")
        {
            Result.clear();
        }
        if (Result.empty() || Result.back() != '/')
        {
            Result.push_back('/');
        }
        Result.append(Session);
        if (Sequence)
        {
            Result.push_back('/');
            Result.append(std::to_string(*Sequence));
        }
        return Result;
    }

    [[nodiscard]] inline auto ParseSplitPath(
        std::string_view Base,
        std::string_view Path,
        const bool RequireSequence) -> std::optional<SplitPath>
    {
        std::string Prefix(Base);
        if (Prefix.empty() || Prefix.back() != '/')
        {
            Prefix.push_back('/');
        }
        if (Path.rfind(Prefix, 0) != 0)
        {
            return std::nullopt;
        }
        auto Suffix = Path.substr(Prefix.size());
        if (Suffix.empty())
        {
            return std::nullopt;
        }
        const auto Separator = Suffix.find('/');
        SplitPath Result;
        if (Separator == std::string_view::npos)
        {
            if (RequireSequence)
            {
                return std::nullopt;
            }
            Result.Session = std::string(Suffix);
            return Result;
        }
        if (RequireSequence && Separator + 1 >= Suffix.size())
        {
            return std::nullopt;
        }
        if (!RequireSequence || Separator == 0 || Suffix.find('/', Separator + 1) != std::string_view::npos)
        {
            return std::nullopt;
        }
        Result.Session = std::string(Suffix.substr(0, Separator));
        const auto SequenceText = Suffix.substr(Separator + 1);
        const auto [End, Error] = std::from_chars(
            SequenceText.data(), SequenceText.data() + SequenceText.size(), Result.Sequence);
        if (Result.Session.empty() || Error != std::errc{} ||
            End != SequenceText.data() + SequenceText.size())
        {
            return std::nullopt;
        }
        Result.HasSequence = true;
        return Result;
    }

    [[nodiscard]] inline auto NextSplitSessionId() -> std::string
    {
        static std::atomic<std::uint64_t> Counter{1};
        const auto Value = Counter.fetch_add(1, std::memory_order_relaxed);
        char Buffer[32]{};
        const auto [End, Error] = std::to_chars(Buffer, Buffer + sizeof(Buffer), Value, 16);
        if (Error != std::errc{})
        {
            return "1";
        }
        return std::string(Buffer, End);
    }

} // namespace Prism::Xhttp::Detail
