/**
 * @file InteropHysteria2ClientWire.hpp
 * @brief Hysteria2 客户端互操作请求编码、响应解析与整流写入。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

#include <Prism/Protocols/Quic/StreamAdapter.hpp>

namespace Prism::Testing::Integration::Hysteria2::Interop::ClientWire
{
    inline auto AppendVarint(std::vector<std::byte> &Output, const std::uint64_t Value) -> void
    {
        if (Value <= 63)
        {
            Output.push_back(static_cast<std::byte>(Value));
            return;
        }
        if (Value <= 16383)
        {
            Output.push_back(static_cast<std::byte>((Value >> 8U) | 0x40U));
            Output.push_back(static_cast<std::byte>(Value));
            return;
        }
        if (Value <= 1073741823)
        {
            Output.push_back(static_cast<std::byte>((Value >> 24U) | 0x80U));
            Output.push_back(static_cast<std::byte>(Value >> 16U));
            Output.push_back(static_cast<std::byte>(Value >> 8U));
            Output.push_back(static_cast<std::byte>(Value));
            return;
        }
        for (std::size_t Index = 0; Index < 8; ++Index)
        {
            const auto Shift = static_cast<unsigned>((7U - Index) * 8U);
            std::uint64_t Prefix = 0;
            if (Index == 0)
            {
                Prefix = 0xC0U;
            }
            Output.push_back(static_cast<std::byte>((Value >> Shift) | Prefix));
        }
    }

    [[nodiscard]] inline auto ReadVarint(
        const std::vector<std::byte> &Data,
        std::size_t &Offset,
        std::uint64_t &Value) -> bool
    {
        if (Offset >= Data.size())
        {
            return false;
        }
        const auto First = std::to_integer<std::uint8_t>(Data[Offset]);
        const auto Length = std::size_t{1U} << (First >> 6U);
        if (Offset + Length > Data.size())
        {
            return false;
        }
        Value = First & 0x3FU;
        for (std::size_t Index = 1; Index < Length; ++Index)
        {
            Value = (Value << 8U) | std::to_integer<std::uint8_t>(Data[Offset + Index]);
        }
        Offset += Length;
        return true;
    }

    [[nodiscard]] inline auto MakeTcpRequest(
        std::string_view Target,
        std::span<const std::byte> Payload) -> std::vector<std::byte>
    {
        std::vector<std::byte> Output;
        AppendVarint(Output, 0x401);
        AppendVarint(Output, Target.size());
        for (const auto Character : Target)
        {
            Output.push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
        }
        AppendVarint(Output, 64);
        Output.insert(Output.end(), 64, std::byte{'a'});
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    [[nodiscard]] inline auto ParseResponse(
        const std::vector<std::byte> &Data,
        std::size_t &HeaderSize,
        std::uint8_t &Status) -> bool
    {
        if (Data.empty())
        {
            return false;
        }
        Status = std::to_integer<std::uint8_t>(Data[0]);
        std::size_t Offset = 1;
        std::uint64_t MessageLength = 0;
        std::uint64_t PaddingLength = 0;
        if (!ReadVarint(Data, Offset, MessageLength) || MessageLength > 2048 ||
            MessageLength > Data.size() - Offset)
        {
            return false;
        }
        Offset += static_cast<std::size_t>(MessageLength);
        if (!ReadVarint(Data, Offset, PaddingLength) || PaddingLength > 4096 ||
            PaddingLength > Data.size() - Offset)
        {
            return false;
        }
        Offset += static_cast<std::size_t>(PaddingLength);
        HeaderSize = Offset;
        return true;
    }

    inline auto WriteAll(
        const Prism::Quic::SharedStreamProvider &Provider,
        std::span<const std::byte> Data) -> boost::asio::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            std::error_code Error;
            const auto Written = co_await Provider->Write(Data.subspan(Offset), Error);
            const auto Remaining = Data.size() - Offset;
            if (Written > Remaining)
            {
                co_return false;
            }
            Offset += Written;
            if (Error || Written == 0)
            {
                co_return false;
            }
        }
        co_return true;
    }
}
