/**
 * @file TcpEcho.hpp
 * @brief Hysteria2 互操作夹具的请求帧组装与发送证据。
 * @details 输入借用到本次同步解析完成；输出拥有待写字节，纯解析不声明 peer delivery。
 *          互操作端点和分段回归 CPP 共用同一边界，不承载 GoogleTest 正文。
 */
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Utility/Crypto/Blake3.hpp>

namespace Prism::Testing::Integration::Hysteria2
{
    inline constexpr std::string_view ExpectedTcpPayload{"hello hysteria2 from go"};
    struct StreamState
    {
        std::vector<std::byte> Pending;
        bool RequestDone{false};
    };

    struct TcpEchoEvidence final
    {
        bool RequestParsed{false};
        bool ResponseWriteCompleted{false};
        bool WriteFinRequested{false};
        /** @brief 保留原生 QUIC 写半关闭拒收，不把失败折叠为 FIN 已发送。 */
        std::optional<Prism::Fault::Failure> WriteFinFailure{};
        std::size_t PayloadBytes{0};
        std::array<std::uint8_t, 32> PayloadHash{};
        std::vector<std::byte> WrittenPayload;
    };

    [[nodiscard]] inline auto ReadVarint(const std::vector<std::byte> &Data, std::size_t &Offset,
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
            auto Prefix = 0U;
            if (Index == 0)
            {
                Prefix = 0xC0U;
            }
            Output.push_back(static_cast<std::byte>((Value >> Shift) | Prefix));
        }
    }

    [[nodiscard]] inline auto MakeTcpResponse(std::span<const std::byte> Payload) -> std::vector<std::byte>
    {
        std::vector<std::byte> Output;
        Output.reserve(3U + Payload.size());
        Output.push_back(std::byte{0});
        AppendVarint(Output, 0);
        AppendVarint(Output, 0);
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    struct TcpDataInput
    {
        StreamState &State;
        std::span<const std::byte> Data;
        bool Fin;
        TcpEchoEvidence &Evidence;
    };

    struct RawAction
    {
        std::vector<std::byte> Data;
        std::size_t ResponseHeaderBytes{0};
        bool Fin{false};
        bool Stop{false};
    };

    [[nodiscard]] inline auto HashPayload(std::span<const std::byte> Data)
        -> std::array<std::uint8_t, 32>
    {
        return Prism::Crypto::Hash(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size()));
    }

    [[nodiscard]] inline auto HandleTcpData(TcpDataInput Input) -> RawAction
    {
        RawAction Action;
        if (Input.State.RequestDone)
        {
            Action.Data.assign(Input.Data.begin(), Input.Data.end());
            Action.Fin = Input.Fin;
            Action.Stop = Input.Fin;
            return Action;
        }

        Input.State.Pending.insert(Input.State.Pending.end(), Input.Data.begin(), Input.Data.end());
        std::size_t Offset = 0;
        std::uint64_t FrameType = 0;
        std::uint64_t AddressLength = 0;
        std::uint64_t PaddingLength = 0;
        if (!ReadVarint(Input.State.Pending, Offset, FrameType) || FrameType != 0x401 ||
            !ReadVarint(Input.State.Pending, Offset, AddressLength) || AddressLength == 0 ||
            AddressLength > 2048 || Offset + AddressLength > Input.State.Pending.size())
        {
            if (Input.Fin)
            {
                Action.Stop = true;
            }
            return Action;
        }
        Offset += static_cast<std::size_t>(AddressLength);
        if (!ReadVarint(Input.State.Pending, Offset, PaddingLength) || PaddingLength > 4096 ||
            Offset + PaddingLength > Input.State.Pending.size())
        {
            if (Input.Fin)
            {
                Action.Stop = true;
            }
            return Action;
        }
        Offset += static_cast<std::size_t>(PaddingLength);
        Input.State.RequestDone = true;
        Input.Evidence.RequestParsed = true;
        Action.Data = MakeTcpResponse(std::span<const std::byte>(Input.State.Pending).subspan(Offset));
        Action.ResponseHeaderBytes = 3;
        Input.State.Pending.clear();
        Action.Fin = Input.Fin;
        Action.Stop = Input.Fin;
        return Action;
    }

    /** @brief 仅在全量 Write 完成后累计 payload；头部不算已完成的回显。 */
    [[nodiscard]] inline auto RecordWritten(TcpEchoEvidence &Evidence, const RawAction &Action) -> bool
    {
        if (Action.ResponseHeaderBytes > Action.Data.size()) return false;
        const auto Payload = std::span<const std::byte>(Action.Data).subspan(Action.ResponseHeaderBytes);
        if (Evidence.WrittenPayload.size() > ExpectedTcpPayload.size() ||
            Payload.size() > ExpectedTcpPayload.size() - Evidence.WrittenPayload.size()) return false;
        Evidence.WrittenPayload.insert(Evidence.WrittenPayload.end(), Payload.begin(), Payload.end());
        Evidence.PayloadBytes = Evidence.WrittenPayload.size();
        Evidence.PayloadHash = HashPayload(Evidence.WrittenPayload);
        Evidence.ResponseWriteCompleted = Evidence.PayloadBytes == ExpectedTcpPayload.size();
        return true;
    }

}
