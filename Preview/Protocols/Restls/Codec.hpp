/**
 * @file Codec.hpp
 * @brief Restls 认证编解码（纯函数，BLAKE3）
 * @details 对齐 C++ include/prism/handshake/restls/crypto.hpp 与
 * restls-Client-go：
 *          - DeriveSecret：BLAKE3 DeriveKey(SecretCtx, Password) → 32B
 *          - ComputeServerMask：BLAKE3 keyed(Secret, ServerRandom) → 16B
 *          - ComputeAuthMac：BLAKE3 keyed(Secret, ServerRandom + direction +
 *            counter + [ClientFinished] + TlsHeader + Payload) → 8B
 *          - ComputeMask：BLAKE3 keyed(Secret, ServerRandom + direction +
 *            counter + PlaintextSample[:32]) → 4B
 * @note AuthMacInput/MaskInput 的公共字段名称保持兼容。
 * @note 参考 restls-Client-go 协议规范。
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <blake3.h>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Restls/Types.hpp>

namespace Preview::Restls
{

    /**
     * @struct FrameOptions
     * @brief Restls TLS ApplicationData 记录构造参数
     */
    struct FrameOptions final
    {
        std::span<const std::uint8_t, 32> Secret;
        std::span<const std::uint8_t, 32> ServerRandom;
        FlowDirection Direction{FlowDirection::ToClient};
        std::uint64_t Counter{0};
        std::span<const std::uint8_t> ClientFinished;
        std::span<const std::uint8_t> Data;
        std::size_t PaddingLength{0};
        std::uint8_t Command{CmdTypeNoop};
        std::uint8_t CommandArgument{0};
    };

    /**
     * @struct DecodeOptions
     * @brief Restls TLS ApplicationData 记录解析参数
     */
    struct DecodeOptions final
    {
        std::span<const std::uint8_t, 32> Secret;
        std::span<const std::uint8_t, 32> ServerRandom;
        FlowDirection Direction{FlowDirection::ToClient};
        std::uint64_t Counter{0};
        std::span<const std::uint8_t> ClientFinished;
    };

    /**
     * @struct DecodedFrame
     * @brief 已认证的 Restls 应用数据记录
     */
    struct DecodedFrame final
    {
        std::uint8_t Command{CmdTypeNoop};
        std::uint8_t CommandArgument{0};
        std::size_t PaddingLength{0};
        std::vector<std::uint8_t> Data;
    };

    /**
     * @brief 从密码派生 RestlsSecret
     * @param Password 认证密码
     * @return 32 字节 RestlsSecret
     * @details BLAKE3 DeriveKey 模式，Context = "restls-traffic-key"。
     */
    [[nodiscard]] inline auto DeriveSecret(std::string_view Password)
        -> std::array<std::uint8_t, 32>
    {
        blake3_hasher Hasher;
        blake3_hasher_init_derive_key(&Hasher, SecretCtx.data());
        blake3_hasher_update(&Hasher, reinterpret_cast<const std::uint8_t *>(Password.data()),
                             Password.size());
        std::array<std::uint8_t, 32> Secret{};
        blake3_hasher_finalize(&Hasher, Secret.data(), Secret.size());
        return Secret;
    }

    /**
     * @brief 计算服务端认证掩码
     * @param Secret RestlsSecret（32 字节）
     * @param ServerRandom TLS ServerHello 随机数（32 字节）
     * @return 16 字节认证掩码
     * @details BLAKE3 keyed(Secret, ServerRandom)，输出截断 16 字节。
     */
    [[nodiscard]] inline auto ComputeServerMask(
        std::span<const std::uint8_t, 32> Secret,
        std::span<const std::uint8_t, 32> ServerRandom)
        -> std::array<std::uint8_t, HsMaclen>
    {
        blake3_hasher Hasher;
        blake3_hasher_init_keyed(&Hasher, Secret.data());
        blake3_hasher_update(&Hasher, ServerRandom.data(), ServerRandom.size());
        std::array<std::uint8_t, HsMaclen> Mask{};
        blake3_hasher_finalize(&Hasher, Mask.data(), Mask.size());
        return Mask;
    }

    /**
     * @brief 计算应用数据认证 MAC
     * @param Secret RestlsSecret（32 字节）
     * @param ServerRandom TLS 随机数（32 字节）
     * @param Direction 数据流方向
     * @param Counter 记录计数器
     * @param ClientFinished 客户端 Finished 消息（仅首次 c2s，否则为空）
     * @param TlsHeader TLS 记录头（5 字节）
     * @param PayloadAfterMac auth_mac 之后的所有数据
     * @return 8 字节认证 MAC
     * @details 输入序列：ServerRandom + direction + counter(8B BE) +
     * [ClientFinished] + TlsHeader + PayloadAfterMac。
     */
    /// 认证 MAC 输入（对齐主库 AuthMacInput）
    struct AuthMacInput
    {
        std::span<const std::uint8_t, 32> Secret;            ///< RestlsSecret（32 字节）
        std::span<const std::uint8_t, 32> ServerRandom;     ///< TLS 随机数（32 字节）
        FlowDirection direction{FlowDirection::ToClient}; ///< 数据流方向
        std::uint64_t counter{0};                            ///< 记录计数器
        std::span<const std::uint8_t> ClientFinished;       ///< 客户端 Finished（首次 c2s）
        std::span<const std::uint8_t> TlsHeader;            ///< TLS 记录头（5 字节）
        std::span<const std::uint8_t> PayloadAfterMac;     ///< auth_mac 之后的数据
    };

    /**
     * @brief 计算应用数据认证 MAC
     * @param Input 输入参数
     * @return 8 字节认证 MAC
     * @details 输入序列：ServerRandom + direction + counter(8B BE) +
     * [ClientFinished] + TlsHeader + PayloadAfterMac。
     */
    [[nodiscard]] inline auto ComputeAuthMac(const AuthMacInput &Input)
        -> std::array<std::uint8_t, AppdataMaclen>
    {
        blake3_hasher Hasher;
        blake3_hasher_init_keyed(&Hasher, Input.Secret.data());
        blake3_hasher_update(&Hasher, Input.ServerRandom.data(), Input.ServerRandom.size());
        std::string_view Direction;
        if (Input.direction == FlowDirection::ToClient)
        {
            Direction = DirToclient;
        }
        else
        {
            Direction = DirToserver;
        }
        blake3_hasher_update(
            &Hasher,
            reinterpret_cast<const std::uint8_t *>(Direction.data()),
            Direction.size());
        std::array<std::uint8_t, 8> CounterBytes{};
        for (std::size_t I = 0; I < 8; ++I)
        {
            CounterBytes[I] = static_cast<std::uint8_t>((Input.counter >> (56 - 8 * I)) & 0xFF);
        }
        blake3_hasher_update(&Hasher, CounterBytes.data(), CounterBytes.size());
        if (!Input.ClientFinished.empty())
        {
            blake3_hasher_update(
                &Hasher,
                Input.ClientFinished.data(),
                Input.ClientFinished.size());
        }
        blake3_hasher_update(&Hasher, Input.TlsHeader.data(), Input.TlsHeader.size());
        blake3_hasher_update(&Hasher, Input.PayloadAfterMac.data(), Input.PayloadAfterMac.size());
        std::array<std::uint8_t, AppdataMaclen> Mac{};
        blake3_hasher_finalize(&Hasher, Mac.data(), Mac.size());
        return Mac;
    }

    /// 掩码输入（对齐主库 MaskInput）
    struct MaskInput
    {
        std::span<const std::uint8_t, 32> Secret;            ///< RestlsSecret（32 字节）
        std::span<const std::uint8_t, 32> ServerRandom;     ///< TLS 随机数（32 字节）
        FlowDirection direction{FlowDirection::ToClient}; ///< 数据流方向
        std::uint64_t counter{0};                            ///< 记录计数器
        std::span<const std::uint8_t> PlaintextSample;      ///< 明文样本（XOR 之前）
    };

    /**
     * @brief 计算数据掩码（XOR 掩码，基于明文）
     * @param Input 输入参数
     * @return 4 字节 XOR 掩码
     * @details 输入序列：ServerRandom + direction + counter(8B BE) + Sample[:32]。
     */
    [[nodiscard]] inline auto ComputeMask(const MaskInput &Input)
        -> std::array<std::uint8_t, MaskLen>
    {
        blake3_hasher Hasher;
        blake3_hasher_init_keyed(&Hasher, Input.Secret.data());
        blake3_hasher_update(&Hasher, Input.ServerRandom.data(), Input.ServerRandom.size());
        std::string_view Direction;
        if (Input.direction == FlowDirection::ToClient)
        {
            Direction = DirToclient;
        }
        else
        {
            Direction = DirToserver;
        }
        blake3_hasher_update(
            &Hasher,
            reinterpret_cast<const std::uint8_t *>(Direction.data()),
            Direction.size());
        std::array<std::uint8_t, 8> CounterBytes{};
        for (std::size_t I = 0; I < 8; ++I)
        {
            CounterBytes[I] = static_cast<std::uint8_t>((Input.counter >> (56 - 8 * I)) & 0xFF);
        }
        blake3_hasher_update(&Hasher, CounterBytes.data(), CounterBytes.size());
        const auto SampleLen = std::min(Input.PlaintextSample.size(), std::size_t{32});
        if (SampleLen > 0)
        {
            blake3_hasher_update(&Hasher, Input.PlaintextSample.data(), SampleLen);
        }
        std::array<std::uint8_t, MaskLen> Mask{};
        blake3_hasher_finalize(&Hasher, Mask.data(), Mask.size());
        return Mask;
    }

    /**
     * @brief 构造完整 Restls ApplicationData TLS 记录
     * @param Input 构造参数
     * @return 错误码与完整 wire；失败时 wire 为空
     * @details 记录布局为 TLS 头 + auth_mac + masked_len/cmd + data + padding。
     */
    [[nodiscard]] inline auto BuildFrame(const FrameOptions &Input)
        -> std::pair<Error, std::vector<std::uint8_t>>
    {
        if (Input.Data.size() > MaxDataLength ||
            Input.PaddingLength > MaxRecordPayload - AuthHdrlen - Input.Data.size())
        {
            return {Error::BadLength, {}};
        }

        const auto PayloadLength = AuthHdrlen + Input.Data.size() + Input.PaddingLength;
        if (PayloadLength > 0xffffU)
        {
            return {Error::BadLength, {}};
        }

        std::vector<std::uint8_t> Wire(TlsHdrlen + PayloadLength, 0);
        Wire[0] = TlsApplicationData;
        Wire[1] = 0x03;
        Wire[2] = 0x03;
        Wire[3] = static_cast<std::uint8_t>(PayloadLength >> 8U);
        Wire[4] = static_cast<std::uint8_t>(PayloadLength);

        auto *Payload = Wire.data() + TlsHdrlen;
        Payload[AppdataMaclen] = static_cast<std::uint8_t>(Input.Data.size() >> 8U);
        Payload[AppdataMaclen + 1] = static_cast<std::uint8_t>(Input.Data.size());
        Payload[AppdataMaclen + 2] = Input.Command;
        Payload[AppdataMaclen + 3] = Input.CommandArgument;
        std::copy(Input.Data.begin(), Input.Data.end(), Payload + AuthHdrlen);

        const auto SampleLength = std::min<std::size_t>(32, PayloadLength - AuthHdrlen);
        const auto Mask = ComputeMask(MaskInput{
            .Secret = Input.Secret,
            .ServerRandom = Input.ServerRandom,
            .direction = Input.Direction,
            .counter = Input.Counter,
            .PlaintextSample = std::span<const std::uint8_t>(Payload + AuthHdrlen, SampleLength)});
        for (std::size_t Index = 0; Index < 4; ++Index)
        {
            Payload[AppdataMaclen + Index] ^= Mask[Index];
        }

        const auto AuthMac = ComputeAuthMac(AuthMacInput{
            .Secret = Input.Secret,
            .ServerRandom = Input.ServerRandom,
            .direction = Input.Direction,
            .counter = Input.Counter,
            .ClientFinished = Input.ClientFinished,
            .TlsHeader = std::span<const std::uint8_t>(Wire.data(), TlsHdrlen),
            .PayloadAfterMac = std::span<const std::uint8_t>(Payload + AppdataMaclen,
                                                              PayloadLength - AppdataMaclen)});
        std::copy(AuthMac.begin(), AuthMac.end(), Payload);
        return {Error::None, std::move(Wire)};
    }

    /**
     * @brief 解析并认证完整 Restls ApplicationData TLS 记录
     * @param Wire 完整记录
     * @param Options 解析参数
     * @param Output 输出的明文帧
     * @return 错误码
     */
    [[nodiscard]] inline auto DecodeFrame(std::span<const std::uint8_t> Wire,
                                          const DecodeOptions &Options,
                                          DecodedFrame &Output) -> Error
    {
        Output = {};
        if (Wire.size() < TlsHdrlen)
        {
            return Error::NeedMore;
        }
        if (Wire[0] != TlsApplicationData || Wire[1] != 0x03 || Wire[2] != 0x03)
        {
            return Error::BadMagic;
        }

        const auto PayloadLength = (static_cast<std::size_t>(Wire[3]) << 8U) | Wire[4];
        if (PayloadLength < AuthHdrlen || PayloadLength > MaxRecordPayload)
        {
            return Error::BadLength;
        }
        if (Wire.size() < TlsHdrlen + PayloadLength)
        {
            return Error::NeedMore;
        }
        if (Wire.size() != TlsHdrlen + PayloadLength)
        {
            return Error::BadLength;
        }

        const auto *Payload = Wire.data() + TlsHdrlen;
        const auto ExpectedMac = ComputeAuthMac(AuthMacInput{
            .Secret = Options.Secret,
            .ServerRandom = Options.ServerRandom,
            .direction = Options.Direction,
            .counter = Options.Counter,
            .ClientFinished = Options.ClientFinished,
            .TlsHeader = Wire.first(TlsHdrlen),
            .PayloadAfterMac = std::span<const std::uint8_t>(Payload + AppdataMaclen,
                                                              PayloadLength - AppdataMaclen)});
        std::uint8_t Difference = 0;
        for (std::size_t Index = 0; Index < AppdataMaclen; ++Index)
        {
            Difference |= static_cast<std::uint8_t>(Payload[Index] ^ ExpectedMac[Index]);
        }
        if (Difference != 0)
        {
            return Error::BadAuth;
        }

        const auto SampleLength = std::min<std::size_t>(32, PayloadLength - AuthHdrlen);
        const auto Mask = ComputeMask(MaskInput{
            .Secret = Options.Secret,
            .ServerRandom = Options.ServerRandom,
            .direction = Options.Direction,
            .counter = Options.Counter,
            .PlaintextSample = std::span<const std::uint8_t>(Payload + AuthHdrlen, SampleLength)});
        std::array<std::uint8_t, 4> LengthAndCommand{};
        std::copy_n(Payload + AppdataMaclen, LengthAndCommand.size(), LengthAndCommand.begin());
        for (std::size_t Index = 0; Index < LengthAndCommand.size(); ++Index)
        {
            LengthAndCommand[Index] ^= Mask[Index];
        }

        const auto DataLength = (static_cast<std::size_t>(LengthAndCommand[0]) << 8U) |
                                LengthAndCommand[1];
        if (DataLength > PayloadLength - AuthHdrlen)
        {
            return Error::BadLength;
        }

        Output.Command = LengthAndCommand[2];
        Output.CommandArgument = LengthAndCommand[3];
        Output.PaddingLength = PayloadLength - AuthHdrlen - DataLength;
        Output.Data.assign(Payload + AuthHdrlen, Payload + AuthHdrlen + DataLength);
        return Error::None;
    }

    /**
     * @brief 对首个后端加密记录应用 Restls ServerMask
     * @param Record 后端返回的完整 TLS ApplicationData 记录
     * @param Secret RestlsSecret
     * @param ServerRandom TLS ServerHello random
     * @return 错误码与发给客户端的记录
     */
    [[nodiscard]] inline auto ProtectFirstEncrypted(
        std::span<const std::uint8_t> Record,
        std::span<const std::uint8_t, 32> Secret,
        std::span<const std::uint8_t, 32> ServerRandom)
        -> std::pair<Error, std::vector<std::uint8_t>>
    {
        if (Record.size() < TlsHdrlen)
        {
            return {Error::NeedMore, {}};
        }
        if (Record[0] != TlsApplicationData || Record[1] != 0x03 || Record[2] != 0x03)
        {
            return {Error::BadMagic, {}};
        }
        const auto PayloadLength = (static_cast<std::size_t>(Record[3]) << 8U) | Record[4];
        if (PayloadLength == 0 || PayloadLength > 0xffffU)
        {
            return {Error::BadLength, {}};
        }
        if (Record.size() < TlsHdrlen + PayloadLength)
        {
            return {Error::NeedMore, {}};
        }
        if (Record.size() != TlsHdrlen + PayloadLength)
        {
            return {Error::BadLength, {}};
        }

        std::vector<std::uint8_t> Protected(Record.begin(), Record.end());
        const auto Mask = ComputeServerMask(Secret, ServerRandom);
        const auto XorLength = std::min(HsMaclen, PayloadLength);
        for (std::size_t Index = 0; Index < XorLength; ++Index)
        {
            Protected[TlsHdrlen + Index] ^= Mask[Index];
        }
        return {Error::None, std::move(Protected)};
    }

} // namespace Preview::Restls
