/** @file Probe.cpp @brief 首包预读与协议类型探测实现。 */
#include <Prism/Runtime/Recognition/Probe.hpp>

#include <Prism/Transport/Preview.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>

namespace Prism::Recognition
{
    auto Detect(const std::span<const std::uint8_t> Data) noexcept
        -> Prism::Contract::ProtocolType
    {
        if (Data.empty())
        {
            return Prism::Contract::ProtocolType::Unknown;
        }
        switch (Data[0])
        {
        case 0x05:
            // SOCKS5 Greeting 至少包含版本和 NMETHODS；限定方法数量范围，
            // 避免随机 SS2022 salt 仅因首字节为 0x05 被误判。
            if (Data.size() < 2)
            {
                return Prism::Contract::ProtocolType::Unknown;
            }
            if (Data[1] >= 1 && Data[1] <= 16)
            {
                return Prism::Contract::ProtocolType::Socks5;
            }
            return Prism::Contract::ProtocolType::Unknown;
        case 0x16:
            if (Data.size() >= 2 && Data[1] == 0x03)
            {
                return Prism::Contract::ProtocolType::Tls;
            }
            return Prism::Contract::ProtocolType::Unknown;
        default:
            break;
        }
        // VLESS 结构化识别（Xray 首字节为 version 0x00）：仅在预读窗口内有效——
        // Probe 最多预读 24 字节（见 Probe.hpp MaxProbeSize），头部固定部分
        // 已占 22 字节，故仅 addnl ≤ 2 可命中；更长 addons 无法在窗口内完成
        // 校验，只能回落到上方 "VLESS" 魔数路径
        if (Data.size() >= 18 && Data[0] == 0x00)
        {
            const std::size_t Addnl = Data[17];
            const std::size_t Need = 18 + Addnl + 4;
            if (Data.size() >= Need)
            {
                const auto Cmd = Data[18 + Addnl];
                const auto Atyp = Data[21 + Addnl];
                if ((Cmd == 0x01 || Cmd == 0x02) && (Atyp == 0x01 || Atyp == 0x02 || Atyp == 0x03))
                {
                    return Prism::Contract::ProtocolType::Vless;
                }
            }
        }
        // Trojan 首包以 SHA-224 凭据文本开始；没有配置密码时不能安全猜测。
        // VMess AuthID 首字节没有稳定魔数；任意 0x01 都可能是随机流量，
        // 不在无配置的 legacy 探测路径中误判，MixedTrial 由候选认证确认。
        // HTTP 方法前缀；保持与生产 analyzer 的方法集合一致。
        constexpr std::string_view Methods[] = {"GET ", "POST ", "CONNECT ", "PUT ", "DELETE ", "HEAD ",
            "OPTIONS ", "TRACE ", "PATCH "};
        for (const auto& Method : Methods)
        {
            if (Data.size() >= Method.size() &&
                std::string_view(reinterpret_cast<const char*>(Data.data()), Method.size()) == Method)
            {
                return Prism::Contract::ProtocolType::Http;
            }
        }
        return Prism::Contract::ProtocolType::Unknown;
    }

    auto CouldBeProtocolPrefix(std::span<const std::uint8_t> Data) noexcept -> bool
    {
        if (Data.empty())
        {
            return false;
        }

        const auto StartsWith = [Data](const std::span<const std::uint8_t> Prefix)
        {
            return Data.size() <= Prefix.size() &&
                std::equal(Data.begin(), Data.end(), Prefix.begin());
        };

        // TLS 在出现不匹配字节后即可确定不是候选协议；Trojan 没有稳定首包魔数，
        // 必须由配置候选凭据校验，不能在 legacy probe 中等待 CRLF 序列。
        constexpr std::array<std::uint8_t, 2> TlsPrefix{0x16, 0x03};
        if (StartsWith(TlsPrefix))
        {
            return true;
        }
        if (Data[0] == 0x16)
        {
            return false;
        }

        // SOCKS5 需要第二字节 NMETHODS 才能确认；非法方法数量立即停止等待。
        if (Data[0] == 0x05)
        {
            return Data.size() < 2;
        }

        // 结构化 VLESS 以版本 0 开始，需要固定头和受限附加字段才能校验。
        if (Data[0] == 0x00)
        {
            if (Data.size() < 18)
            {
                return true;
            }
            const auto AddonLength = static_cast<std::size_t>(Data[17]);
            const auto Need = 18 + AddonLength + 4;
            return Need <= MaxProbeSize && Data.size() < Need;
        }

        // HTTP 方法名是首包分片后仍可继续判定的文本前缀。
        constexpr std::string_view Methods[] = {
            "GET ", "POST ", "CONNECT ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "TRACE ", "PATCH "};
        for (const auto Method : Methods)
        {
            if (Data.size() <= Method.size() &&
                std::equal(Data.begin(), Data.end(), Method.begin()))
            {
                return true;
            }
        }
        return false;
    }

    auto Probe(Transmission &transport, std::size_t MaxSize) -> Net::awaitable<ProbeResult>
    {
        ProbeResult Result;
        const auto Peek = (std::min)(MaxSize, MaxProbeSize);

        std::array<std::uint8_t, MaxProbeSize> Bytes{};
        while (Result.PreReadSize < Peek)
        {
            const auto Part = co_await transport.ReadSome(
                std::span<std::byte>(Result.PreRead.data() + Result.PreReadSize,
                    Peek - Result.PreReadSize));
            const auto N = Part.Bytes;
            if (N > Peek - Result.PreReadSize)
            {
                co_return Result;
            }
            for (std::size_t I = 0; I < N; ++I)
            {
                Bytes[Result.PreReadSize + I] = std::to_integer<std::uint8_t>(
                    Result.PreRead[Result.PreReadSize + I]);
            }
            Result.PreReadSize += N;
            Result.Type = Detect(std::span<const std::uint8_t>(Bytes.data(), Result.PreReadSize));
            if (Part.Failure.Failed() || N == 0)
            {
                co_return Result;
            }
            if (Result.Type != Prism::Contract::ProtocolType::Unknown)
            {
                Result.success = true;
                break;
            }
            if (!CouldBeProtocolPrefix(
                    std::span<const std::uint8_t>(Bytes.data(), Result.PreReadSize)))
            {
                break;
            }
        }
        co_return Result;
    }

    auto WrapPreread(SharedTransmission transport, std::span<const std::byte> preread,
        std::shared_ptr<Prism::Memory::BytePool> bytes) -> SharedTransmission
    {
        if (preread.empty())
        {
            return transport;
        }
        const auto Created = Prism::Transport::PreviewTransport::Create(
            transport, Prism::Transport::PrefixInput{preread, std::move(bytes), {}});
        if (!Created)
        {
            return {};
        }
        return *Created;
    }
}
