/** @file QueryIdentity.cpp @brief DNS query wire 编码实现。 */
#include <Prism/Net/Dns/QueryIdentity.hpp>

#include <string_view>

namespace Prism::Network::Dns
{
    auto QueryIdentity::Encode(const std::span<std::uint8_t> Output) const noexcept
        -> std::expected<std::size_t, Fault::Failure>
    {
        if (Parameters.Class != 1 || Parameters.Opcode != 0)
        {
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument, {}});
        }
        const auto Text = Name.View();
        const auto Required = 12 + Text.size() + 2 + 4;
        if (Output.size() < Required)
        {
            return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable, {}});
        }
        for (std::size_t Index = 0; Index < 12; ++Index)
        {
            Output[Index] = 0;
        }
        Output[0] = static_cast<std::uint8_t>(Parameters.Id >> 8);
        Output[1] = static_cast<std::uint8_t>(Parameters.Id);
        Output[2] = 1;
        Output[5] = 1;
        std::size_t Offset = 12;
        std::size_t Start = 0;
        while (Start < Text.size())
        {
            auto End = Text.find('.', Start);
            if (End == std::string_view::npos)
            {
                End = Text.size();
            }
            Output[Offset++] = static_cast<std::uint8_t>(End - Start);
            for (std::size_t Index = Start; Index < End; ++Index)
            {
                Output[Offset++] = static_cast<std::uint8_t>(Text[Index]);
            }
            Start = End + 1;
        }
        Output[Offset++] = 0;
        const auto Type = static_cast<std::uint16_t>(Parameters.Type);
        Output[Offset++] = static_cast<std::uint8_t>(Type >> 8);
        Output[Offset++] = static_cast<std::uint8_t>(Type);
        Output[Offset++] = 0;
        Output[Offset++] = 1;
        return Offset;
    }
}
