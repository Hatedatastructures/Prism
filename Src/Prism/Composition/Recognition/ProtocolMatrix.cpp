/** @file ProtocolMatrix.cpp @brief 静态协议矩阵的名称查询实现。 */

#include <Prism/Composition/Recognition/ProtocolMatrix.hpp>

#include <algorithm>
#include <cstddef>

namespace Prism::Composition::Recognition
{

    auto ProtocolMatrix::SupportsUdp(const std::string_view Name) noexcept -> bool
    {
        return std::any_of(UdpBindings_.begin(), UdpBindings_.end(),
            [Name](const auto& Binding)
            {
                return EqualAscii(Binding.Name, Name);
            });
    }

    auto ProtocolMatrix::FindQuic(const std::string_view Alpn,
        const Prism::Contract::ProtocolType Protocol) noexcept
        -> std::optional<QuicAlpnBinding>
    {
        for (const auto& Binding : QuicBindings_)
        {
            if (Binding.Protocol == Protocol && EqualAscii(Binding.Alpn, Alpn))
            {
                return Binding;
            }
        }
        return std::nullopt;
    }

    auto ProtocolMatrix::ScopeFor(
        const Prism::Contract::ProtocolType Protocol) noexcept -> OperationScope
    {
        if (Protocol == Prism::Contract::ProtocolType::Hysteria2 ||
            Protocol == Prism::Contract::ProtocolType::Tuic)
        {
            return OperationScope::QuicBinding;
        }
        return OperationScope::TcpRecognition;
    }

    auto ProtocolMatrix::EqualAscii(const std::string_view Left,
        const std::string_view Right) noexcept -> bool
    {
        if (Left.size() != Right.size())
            return false;
        for (std::size_t Index = 0; Index < Left.size(); ++Index)
        {
            const auto Lower = [](const char Character) noexcept -> char
            {
                if (Character >= 'A' && Character <= 'Z')
                    return static_cast<char>(Character + ('a' - 'A'));
                return Character;
            };
            if (Lower(Left[Index]) != Lower(Right[Index]))
                return false;
        }
        return true;
    }

} // namespace Prism::Composition::Recognition
