/**
 * @file RequestCodec.hpp
 * @brief Shadowsocks 2022 请求头和握手状态机
 * @details 负责固定头、地址、变长头以及客户端请求 Serializer/Parser。
 *          会话密钥和数据面分块分别位于 KeyDerivation.hpp 与
 *          ChunkCodec.hpp。
 */

#pragma once

#include <boost/asio/buffer.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <limits>
#include <random>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Utility/Crypto/Random.hpp>
#include <preview/Protocols/Common/Address.hpp>
#include <preview/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <preview/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <preview/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    /**
     * @brief 构造固定头明文
     * @param Type 头类型（0x00 请求 / 0x01 响应）
     * @param TimeSec UTC 秒
     * @param VarLen 变长头长度
     * @return 11 字节明文
     */
    [[nodiscard]] inline auto ParseFixedHeader(
        std::uint8_t Type,
        std::uint64_t TimeSec,
        std::uint16_t VarLen)
        -> std::array<std::uint8_t, FixedHdrPlain>
    {
        std::array<std::uint8_t, FixedHdrPlain> Output{};
        Output[0] = Type;
        for (std::size_t I = 0; I < 8; ++I)
        {
            Output[1 + I] = static_cast<std::uint8_t>((TimeSec >> (56 - I * 8)) & 0xFF);
        }
        Output[9] = static_cast<std::uint8_t>((VarLen >> 8) & 0xFF);
        Output[10] = static_cast<std::uint8_t>(VarLen & 0xFF);
        return Output;
    }

    /**
     * @brief 解析出的固定头字段
     */
    struct FixedHeader
    {
        std::uint8_t Type{0};
        std::uint64_t TimeSec{0};
        std::uint16_t VarLen{0};
    };

    /**
     * @brief 解析固定头明文
     * @param Data 11 字节明文
     * @param Out 输出固定头字段
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseFixedHeader(
        std::span<const std::uint8_t> Data,
        FixedHeader &Output) -> Error
    {
        if (Data.size() < FixedHdrPlain)
        {
            return Error::NeedMore;
        }
        Output.Type = Data[0];
        Output.TimeSec = 0;
        for (std::size_t I = 0; I < 8; ++I)
        {
            Output.TimeSec = (Output.TimeSec << 8) | Data[1 + I];
        }
        Output.VarLen = static_cast<std::uint16_t>(Data[9]) << 8 | Data[10];
        return Error::None;
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
     * @param Addr 目标地址
     * @param Out 输出缓冲（追加到末尾）
     */
    template <typename Alloc>
    inline auto EncodeAddress(
        const Address &AddressValue,
        std::vector<std::uint8_t, Alloc> &Output) -> bool
    {
        return Preview::Protocol::Common::EncodeAddress(AddressValue, Output);
    }

    /**
     * @brief 编码地址为独立字节序列
     * @param Addr 目标地址
     * @return 编码后的地址
     */
    [[nodiscard]] inline auto EncodeAddress(const Address &AddressValue)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        if (!EncodeAddress(AddressValue, Output))
        {
            return {};
        }
        return Output;
    }

    /**
     * @brief 解析地址字节
     * @param Data 完整缓冲区
     * @param Output 输出目标地址
     * @param Offset 输入起始偏移，输出结束偏移
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseAddress(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::size_t &Offset) -> Error
    {
        if (Offset >= Data.size())
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[Offset++]);
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Offset < 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> Buffer{};
            std::snprintf(
                Buffer.data(),
                Buffer.size(),
                "%u.%u.%u.%u",
                static_cast<unsigned int>(Data[Offset]),
                static_cast<unsigned int>(Data[Offset + 1]),
                static_cast<unsigned int>(Data[Offset + 2]),
                static_cast<unsigned int>(Data[Offset + 3]));
            Output.Host = Buffer.data();
            Offset += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Offset < 16)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Offset), 16);
            Offset += 16;
            break;
        }
        case AddressType::Domain: {
            if (Offset >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Offset++];
            if (Length == 0)
            {
                return Error::BadAddress;
            }
            if (Data.size() - Offset < Length)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Offset), Length);
            Offset += Length;
            break;
        }
        default: return Error::BadAddress;
        }
        if (Data.size() - Offset < 2)
        {
            return Error::NeedMore;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Offset]) << 8 | Data[Offset + 1];
        Offset += 2;
        return Error::None;
    }

    /**
     * @brief 构造变长头明文（地址 + padding + 初始载荷）
     * @param AddressValue 目标地址
     * @param PaddingLength padding 长度
     * @param Payload 初始载荷（可空）
     * @return 变长头明文
     */
    [[nodiscard]] inline auto BuildVarHeader(
        const Address &AddressValue,
        std::uint16_t PaddingLength,
        std::span<const std::uint8_t> Payload = {})
        -> std::vector<std::uint8_t>
    {
        auto Output = EncodeAddress(AddressValue);
        if (Output.empty())
        {
            return {};
        }
        constexpr auto MaxVarHeaderLength = (std::numeric_limits<std::uint16_t>::max)();
        if (PaddingLength > MaxVarHeaderLength - 2 ||
            Output.size() > MaxVarHeaderLength - 2 - PaddingLength ||
            Payload.size() > MaxVarHeaderLength - 2 - PaddingLength - Output.size())
        {
            return {};
        }
        Output.push_back(static_cast<std::uint8_t>((PaddingLength >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(PaddingLength & 0xFF));
        for (std::uint16_t I = 0; I < PaddingLength; ++I)
        {
            Output.push_back(0);
        }
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    /**
     * @brief 解析变长头明文
     * @param Data 变长头明文
     * @param Output 输出目标地址
     * @param Payload 输出剩余载荷
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseVarHeader(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::span<const std::uint8_t> &Payload) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[0]);
        std::size_t Off = 1;
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Off < 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> Buffer{};
            std::snprintf(
                Buffer.data(),
                Buffer.size(),
                "%u.%u.%u.%u",
                static_cast<unsigned int>(Data[Off]),
                static_cast<unsigned int>(Data[Off + 1]),
                static_cast<unsigned int>(Data[Off + 2]),
                static_cast<unsigned int>(Data[Off + 3]));
            Output.Host = Buffer.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Off < 16)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Off++];
            if (Length == 0)
            {
                return Error::BadAddress;
            }
            if (Data.size() - Off < Length)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Length);
            Off += Length;
            break;
        }
        default: return Error::BadAddress;
        }
        if (Data.size() - Off < 2)
        {
            return Error::NeedMore;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() - Off < 2)
        {
            return Error::NeedMore;
        }
        const auto PaddingLength = static_cast<std::size_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() - Off < PaddingLength)
        {
            return Error::NeedMore;
        }
        Off += PaddingLength;
        Payload = Data.subspan(Off);
        return Error::None;
    }

    /**
     * @brief SS2022 握手消息
     */
    struct Message
    {
        Address dst;
        std::string InitialPayload;
    };

    /**
     * @brief SS2022 握手序列化器
     */
    class Serializer
    {
    public:
        using RandomSource = std::function<int(std::uint8_t *, int)>;
        /**
         * @brief 构造
         * @param Psk 预共享密钥（16 字节）
         */
        explicit Serializer(
            const std::array<std::uint8_t, 16> &Psk,
            RandomSource Source = {})
            : Psk_(Psk), Source_(std::move(Source))
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param MessageValue 消息
         * @param TimeSec UTC 秒
         */
        auto Reset(const Message &MessageValue, std::uint64_t TimeSec) -> void
        {
            Wire_.clear();
            Offset_ = 0;
            Ready_ = false;
            Failed_ = false;
            std::array<std::uint8_t, 16> Salt{};
            bool Filled;
            if (Source_)
            {
                Filled = Preview::Crypto::FillRandom(std::span<std::uint8_t>(Salt), Source_);
            }
            else
            {
                Filled = Preview::Crypto::FillRandom(std::span<std::uint8_t>(Salt));
            }
            if (!Filled)
            {
                Failed_ = true;
                return;
            }
            const auto SessionKeyValue = SessionKey(Psk_, Salt, 16);

            std::random_device RandomDevice;
            const auto PaddingLength = static_cast<std::uint16_t>(1 + RandomDevice() % 16);
            std::vector<std::uint8_t> VariableHeader;
            const auto AddressBytes = EncodeAddress(MessageValue.dst);
            if (AddressBytes.empty())
            {
                Failed_ = true;
                return;
            }
            VariableHeader.insert(VariableHeader.end(), AddressBytes.begin(), AddressBytes.end());
            VariableHeader.push_back(static_cast<std::uint8_t>((PaddingLength >> 8) & 0xFF));
            VariableHeader.push_back(static_cast<std::uint8_t>(PaddingLength & 0xFF));
            for (std::uint16_t I = 0; I < PaddingLength; ++I)
            {
                VariableHeader.push_back(static_cast<std::uint8_t>(RandomDevice() & 0xFF));
            }
            VariableHeader.insert(
                VariableHeader.end(),
                MessageValue.InitialPayload.begin(),
                MessageValue.InitialPayload.end());
            if (VariableHeader.size() > (std::numeric_limits<std::uint16_t>::max)())
            {
                Failed_ = true;
                return;
            }

            const auto Fixed = ParseFixedHeader(
                HeaderTypeClient,
                TimeSec,
                static_cast<std::uint16_t>(VariableHeader.size()));
            ChunkCodec Codec(SessionKeyValue);
            const auto FixedEncrypted = Codec.SealRaw(Fixed);
            const auto VariableEncrypted = Codec.SealRaw(VariableHeader);
            if (FixedEncrypted.empty() || VariableEncrypted.empty())
            {
                Failed_ = true;
                return;
            }

            Wire_.clear();
            Wire_.reserve(Salt.size() + FixedEncrypted.size() + VariableEncrypted.size());
            Wire_.insert(Wire_.end(), Salt.begin(), Salt.end());
            Wire_.insert(Wire_.end(), FixedEncrypted.begin(), FixedEncrypted.end());
            Wire_.insert(Wire_.end(), VariableEncrypted.begin(), VariableEncrypted.end());
            Ready_ = !Wire_.empty();
        }

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param ErrorCode 错误码
         * @return 实际写入字节数
         */
        auto Get(
            boost::asio::mutable_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t
        {
            ErrorCode.clear();
            if (!Ready_)
            {
                ErrorCode = make_error_code(Error::IoError);
                return 0;
            }
            const auto N = std::min(Buffer.size(), Wire_.size() - Offset_);
            std::memcpy(Buffer.data(), Wire_.data() + Offset_, N);
            Offset_ += N;
            return N;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return !Failed_ && Ready_ && Offset_ >= Wire_.size();
        }

    private:
        std::array<std::uint8_t, 16> Psk_;
        RandomSource Source_;
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
        bool Ready_{false};
        bool Failed_{false};
    };

    /**
     * @brief SS2022 握手解析器
     */
    class Parser
    {
    public:
        /**
         * @brief 构造
         * @param Psk 预共享密钥（16 字节）
         */
        explicit Parser(const std::array<std::uint8_t, 16> &Psk) : Psk_(Psk)
        {
        }

        /**
         * @brief 增量喂入
         * @param Buffer 输入缓冲区
         * @param ErrorCode 错误码
         * @return 已累积缓冲字节数
         */
        auto Put(
            boost::asio::const_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t
        {
            ErrorCode.clear();
            if (Done_)
            {
                return 0;
            }
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            Buf_.insert(Buf_.end(), Data.begin(), Data.end());
            if (Buf_.size() < 16 + FixedHdrPlain + AeadTagLen)
            {
                ErrorCode = make_error_code(Error::NeedMore);
                return 0;
            }

            const auto Salt = std::span<const std::uint8_t>(Buf_).first(16);
            const auto SessionKeyValue = SessionKey(Psk_, Salt, 16);
            ChunkCodec Codec(SessionKeyValue);
            auto FixedPlain = Codec.OpenRaw(std::span<const std::uint8_t>(Buf_).subspan(
                                                   16, FixedHdrPlain + AeadTagLen));
            if (FixedPlain.size() != FixedHdrPlain || FixedPlain[0] != HeaderTypeClient)
            {
                ErrorCode = make_error_code(Error::AuthFailed);
                return 0;
            }
            FixedHeader FixedHeaderValue;
            if (ParseFixedHeader(FixedPlain, FixedHeaderValue) != Error::None)
            {
                ErrorCode = make_error_code(Error::BadMessage);
                return 0;
            }
            TimeSec_ = FixedHeaderValue.TimeSec;
            const auto VariableLength = static_cast<std::size_t>(FixedHeaderValue.VarLen);
            if (Buf_.size() < 16 + FixedHdrPlain + AeadTagLen + VariableLength + AeadTagLen)
            {
                ErrorCode = make_error_code(Error::NeedMore);
                return 0;
            }
            auto VariablePlain = Codec.OpenRaw(std::span<const std::uint8_t>(Buf_).subspan(
                                                       16 + FixedHdrPlain + AeadTagLen,
                                                       VariableLength + AeadTagLen));
            if (VariablePlain.empty())
            {
                ErrorCode = make_error_code(Error::AuthFailed);
                return 0;
            }

            std::size_t Offset = 0;
            const auto AddressError = ParseAddress(
                std::span<const std::uint8_t>(VariablePlain).subspan(Offset),
                Msg_.dst,
                Offset);
            if (AddressError != Error::None)
            {
                ErrorCode = make_error_code(AddressError);
                return 0;
            }
            if (VariablePlain.size() - Offset < 2)
            {
                ErrorCode = make_error_code(Error::BadMessage);
                return 0;
            }
            const auto PaddingLength =
                static_cast<std::size_t>(VariablePlain[Offset]) << 8 | VariablePlain[Offset + 1];
            Offset += 2;
            if (VariablePlain.size() - Offset < PaddingLength)
            {
                ErrorCode = make_error_code(Error::BadMessage);
                return 0;
            }
            Offset += PaddingLength;
            Msg_.InitialPayload.assign(
                reinterpret_cast<const char *>(VariablePlain.data() + Offset),
                VariablePlain.size() - Offset);
            Done_ = true;
            return Buf_.size();
        }

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Done_;
        }

        /**
         * @brief 解析结果
         * @return 消息引用
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return Msg_;
        }

        /**
         * @brief 获取握手固定头时间戳
         * @return 客户端握手时间戳（UTC 秒）
         */
        [[nodiscard]] auto TimeSec() const noexcept -> std::uint64_t
        {
            return TimeSec_;
        }

        /**
         * @brief 校验握手时间戳是否在允许窗口内
         * @param TimeWindow 允许的绝对误差（秒）
         * @return 时间戳有效返回 true
         */
        [[nodiscard]] auto IsTimestampFresh(std::uint64_t TimeWindow) const noexcept -> bool
        {
            const auto Now = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
            std::uint64_t Difference;
            if (Now >= TimeSec_)
            {
                Difference = Now - TimeSec_;
            }
            else
            {
                Difference = TimeSec_ - Now;
            }
            return Difference <= TimeWindow;
        }

        /**
         * @brief 重置解析状态
         */
        auto Reset() -> void
        {
            Buf_.clear();
            Msg_ = Message{};
            TimeSec_ = 0;
            Done_ = false;
        }

    private:
        std::array<std::uint8_t, 16> Psk_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        std::uint64_t TimeSec_{0};
        bool Done_{false};
    };

} // namespace Preview::Shadowsocks2022
