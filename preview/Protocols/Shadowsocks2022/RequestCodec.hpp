/**
 * @file RequestCodec.hpp
 * @brief Shadowsocks 2022 请求头和握手状态机
 * @details 负责固定头、地址、变长头以及客户端请求 Serializer/Parser。
 *          会话密钥和数据面分块分别位于 KeyDerivation.hpp 与
 *          ChunkCodec.hpp。
 */

#pragma once

#include <boost/asio/buffer.hpp>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <preview/Foundation/Error.hpp>
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
    [[nodiscard]] inline auto ParseFixedHeader(std::uint8_t Type, std::uint64_t TimeSec,
                                                 std::uint16_t VarLen)
        -> std::array<std::uint8_t, FixedHdrPlain>
    {
        std::array<std::uint8_t, FixedHdrPlain> Out{};
        Out[0] = Type;
        for (std::size_t I = 0; I < 8; ++I)
        {
            Out[1 + I] = static_cast<std::uint8_t>((TimeSec >> (56 - I * 8)) & 0xFF);
        }
        Out[9] = static_cast<std::uint8_t>((VarLen >> 8) & 0xFF);
        Out[10] = static_cast<std::uint8_t>(VarLen & 0xFF);
        return Out;
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
    [[nodiscard]] inline auto ParseFixedHeader(std::span<const std::uint8_t> Data, FixedHeader &Out) -> Error
    {
        if (Data.size() < FixedHdrPlain)
        {
            return Error::NeedMore;
        }
        Out.Type = Data[0];
        Out.TimeSec = 0;
        for (std::size_t I = 0; I < 8; ++I)
        {
            Out.TimeSec = (Out.TimeSec << 8) | Data[1 + I];
        }
        Out.VarLen = static_cast<std::uint16_t>(Data[9]) << 8 | Data[10];
        return Error::None;
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
     * @param Addr 目标地址
     * @param Out 输出缓冲（追加到末尾）
     */
    template <typename Alloc>
    inline auto EncodeAddress(const Address &Addr, std::vector<std::uint8_t, Alloc> &Out) -> void
    {
        Preview::Protocol::Common::EncodeAddress(Addr, Out);
    }

    /**
     * @brief 编码地址为独立字节序列
     * @param Addr 目标地址
     * @return 编码后的地址
     */
    [[nodiscard]] inline auto EncodeAddress(const Address &Addr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Out;
        EncodeAddress(Addr, Out);
        return Out;
    }

    /**
     * @brief 解析地址字节
     * @param Data 完整缓冲区
     * @param Addr 输出目标地址
     * @param Off 输入起始偏移，输出结束偏移
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseAddress(std::span<const std::uint8_t> Data, Address &Addr,
                                             std::size_t &Off) -> Error
    {
        if (Off >= Data.size())
        {
            return Error::NeedMore;
        }
        Addr.Type = static_cast<AddressType>(Data[Off++]);
        switch (Addr.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < Off + 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", Data[Off], Data[Off + 1], Data[Off + 2],
                          Data[Off + 3]);
            Addr.Host = buf.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < Off + 16)
            {
                return Error::NeedMore;
            }
            Addr.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Len = Data[Off++];
            if (Data.size() < Off + Len)
            {
                return Error::NeedMore;
            }
            Addr.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Len);
            Off += Len;
            break;
        }
        default: return Error::BadAddress;
        }
        if (Data.size() < Off + 2)
        {
            return Error::NeedMore;
        }
        Addr.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        return Error::None;
    }

    /**
     * @brief 构造变长头明文（地址 + padding + 初始载荷）
     * @param Addr 目标地址
     * @param PadLen padding 长度
     * @param payload 初始载荷（可空）
     * @return 变长头明文
     */
    [[nodiscard]] inline auto BuildVarHeader(const Address &Addr, std::uint16_t PadLen,
                                               std::span<const std::uint8_t> payload = {})
        -> std::vector<std::uint8_t>
    {
        auto Out = EncodeAddress(Addr);
        Out.push_back(static_cast<std::uint8_t>((PadLen >> 8) & 0xFF));
        Out.push_back(static_cast<std::uint8_t>(PadLen & 0xFF));
        for (std::uint16_t I = 0; I < PadLen; ++I)
        {
            Out.push_back(0);
        }
        Out.insert(Out.end(), payload.begin(), payload.end());
        return Out;
    }

    /**
     * @brief 解析变长头明文
     * @param Data 变长头明文
     * @param Addr 输出目标地址
     * @param payload 输出剩余载荷
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseVarHeader(std::span<const std::uint8_t> Data, Address &Addr,
                                               std::span<const std::uint8_t> &payload) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        Addr.Type = static_cast<AddressType>(Data[0]);
        std::size_t Off = 1;
        switch (Addr.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < Off + 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", Data[Off], Data[Off + 1], Data[Off + 2],
                          Data[Off + 3]);
            Addr.Host = buf.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < Off + 16)
            {
                return Error::NeedMore;
            }
            Addr.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Len = Data[Off++];
            if (Data.size() < Off + Len)
            {
                return Error::NeedMore;
            }
            Addr.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Len);
            Off += Len;
            break;
        }
        default: return Error::BadAddress;
        }
        if (Data.size() < Off + 2)
        {
            return Error::NeedMore;
        }
        Addr.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() < Off + 2)
        {
            return Error::NeedMore;
        }
        const auto PadLen = static_cast<std::size_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() < Off + PadLen)
        {
            return Error::NeedMore;
        }
        Off += PadLen;
        payload = Data.subspan(Off);
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
        /**
         * @brief 构造
         * @param psk 预共享密钥（16 字节）
         */
        explicit Serializer(const std::array<std::uint8_t, 16> &psk) : Psk_(psk)
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param msg 消息
         * @param TimeSec UTC 秒
         */
        auto Reset(const Message &msg, std::uint64_t TimeSec) -> void
        {
            std::array<std::uint8_t, 16> Salt{};
            RAND_bytes(Salt.data(), static_cast<int>(Salt.size()));
            const auto key = SessionKey(Psk_, Salt, 16);

            std::random_device rd;
            const auto PadLen = static_cast<std::uint16_t>(1 + rd() % 16);
            std::vector<std::uint8_t> var;
            const auto Addr = EncodeAddress(msg.dst);
            var.insert(var.end(), Addr.begin(), Addr.end());
            var.push_back(static_cast<std::uint8_t>((PadLen >> 8) & 0xFF));
            var.push_back(static_cast<std::uint8_t>(PadLen & 0xFF));
            for (std::uint16_t I = 0; I < PadLen; ++I)
            {
                var.push_back(static_cast<std::uint8_t>(rd() & 0xFF));
            }
            var.insert(var.end(), msg.InitialPayload.begin(), msg.InitialPayload.end());

            const auto Fixed = ParseFixedHeader(HeaderTypeClient, TimeSec, static_cast<std::uint16_t>(var.size()));
            ChunkCodec Codec(key);
            const auto FixedEnc = Codec.SealRaw(Fixed);
            const auto VarEnc = Codec.SealRaw(var);

            Wire_.clear();
            Wire_.reserve(Salt.size() + FixedEnc.size() + VarEnc.size());
            Wire_.insert(Wire_.end(), Salt.begin(), Salt.end());
            Wire_.insert(Wire_.end(), FixedEnc.begin(), FixedEnc.end());
            Wire_.insert(Wire_.end(), VarEnc.begin(), VarEnc.end());
            Offset_ = 0;
        }

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param ec 错误码
         * @return 实际写入字节数
         */
        auto Get(boost::asio::mutable_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
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
            return Offset_ >= Wire_.size();
        }

    private:
        std::array<std::uint8_t, 16> Psk_;
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief SS2022 握手解析器
     */
    class Parser
    {
    public:
        /**
         * @brief 构造
         * @param psk 预共享密钥（16 字节）
         */
        explicit Parser(const std::array<std::uint8_t, 16> &psk) : Psk_(psk)
        {
        }

        /**
         * @brief 增量喂入
         * @param Buffer 输入缓冲区
         * @param ec 错误码
         * @return 已累积缓冲字节数
         */
        auto Put(boost::asio::const_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            Buf_.insert(Buf_.end(), Data.begin(), Data.end());
            if (Buf_.size() < 16 + FixedHdrPlain + AeadTagLen)
            {
                ec = make_error_code(Error::NeedMore);
                return 0;
            }

            const auto Salt = std::span<const std::uint8_t>(Buf_).first(16);
            const auto key = SessionKey(Psk_, Salt, 16);
            ChunkCodec Codec(key);
            auto FixedPlain = Codec.OpenRaw(std::span<const std::uint8_t>(Buf_).subspan(
                                                   16, FixedHdrPlain + AeadTagLen));
            if (FixedPlain.size() != FixedHdrPlain || FixedPlain[0] != HeaderTypeClient)
            {
                ec = make_error_code(Error::AuthFailed);
                return 0;
            }
            const auto VarLen = static_cast<std::size_t>(FixedPlain[9]) << 8 | FixedPlain[10];
            if (Buf_.size() < 16 + FixedHdrPlain + AeadTagLen + VarLen + AeadTagLen)
            {
                ec = make_error_code(Error::NeedMore);
                return 0;
            }
            auto VarPlain = Codec.OpenRaw(std::span<const std::uint8_t>(Buf_).subspan(
                                                 16 + FixedHdrPlain + AeadTagLen,
                                                 VarLen + AeadTagLen));
            if (VarPlain.empty())
            {
                ec = make_error_code(Error::AuthFailed);
                return 0;
            }

            std::size_t Off = 0;
            auto Err = ParseAddress(std::span<const std::uint8_t>(VarPlain).subspan(Off), Msg_.dst, Off);
            if (Err != Error::None)
            {
                ec = make_error_code(Err);
                return 0;
            }
            if (VarPlain.size() < Off + 2)
            {
                ec = make_error_code(Error::BadMessage);
                return 0;
            }
            const auto PadLen = static_cast<std::size_t>(VarPlain[Off]) << 8 | VarPlain[Off + 1];
            Off += 2;
            if (VarPlain.size() < Off + PadLen)
            {
                ec = make_error_code(Error::BadMessage);
                return 0;
            }
            Off += PadLen;
            Msg_.InitialPayload.assign(reinterpret_cast<const char *>(VarPlain.data() + Off),
                                        VarPlain.size() - Off);
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
         * @brief 重置解析状态
         */
        auto Reset() -> void
        {
            Buf_.clear();
            Msg_ = Message{};
            Done_ = false;
        }

    private:
        std::array<std::uint8_t, 16> Psk_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool Done_{false};
    };

} // namespace Preview::Shadowsocks2022
