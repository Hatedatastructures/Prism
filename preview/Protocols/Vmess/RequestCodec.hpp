/**
 * @file RequestCodec.hpp
 * @brief VMess 请求头和请求握手状态机
 * @details 负责请求明文头编解码，以及 Serializer/Parser 的增量握手
 *          状态。认证头 AEAD 与 KDF 位于 Auth.hpp，数据分块位于
 *          ChunkCodec.hpp。
 */

#pragma once

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <limits>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Utility/Crypto/Random.hpp>
#include <preview/Protocols/Vmess/Auth.hpp>
#include <preview/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

    namespace Net = boost::asio;

    /**
     * @brief 请求头附加元数据（IV + Key + V + Padding）
     */
    struct RequestMeta
    {
        std::span<const std::uint8_t, 16> iv;
        std::span<const std::uint8_t, 16> key;
        std::uint8_t v{0};
        std::uint8_t p{0};
    };

    /**
     * @brief 编码请求头明文
     * @param Header 请求头
     * @param Metadata 附加元数据
     * @return 明文字节序列（含 FNV1a 校验）
     */
    [[nodiscard]] inline auto BuildRequestHeader(
        const RequestHeader &Header,
        const RequestMeta &Metadata)
        -> std::vector<std::uint8_t>
    {
        constexpr auto ReserveOverhead = std::size_t{64};
        if (Header.Target.Host.size() > (std::numeric_limits<std::size_t>::max)() - ReserveOverhead)
        {
            return {};
        }
        std::vector<std::uint8_t> Output;
        Output.reserve(ReserveOverhead + Header.Target.Host.size());
        Output.push_back(Header.Version);
        Output.insert(Output.end(), Metadata.iv.begin(), Metadata.iv.end());
        Output.insert(Output.end(), Metadata.key.begin(), Metadata.key.end());
        Output.push_back(Metadata.v);
        Output.push_back(static_cast<std::uint8_t>(Header.opt));
        Output.push_back(static_cast<std::uint8_t>(
            ((Metadata.p & 0x0F) << 4) | static_cast<std::uint8_t>(Header.sec)));
        Output.push_back(Header.reserved);
        Output.push_back(static_cast<std::uint8_t>(Header.Cmd));
        Output.push_back(static_cast<std::uint8_t>((Header.Target.Port >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Header.Target.Port & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Header.Target.Type));
        switch (Header.Target.Type)
        {
        case AddressType::Ipv4: {
            std::array<std::uint8_t, 4> Ipv4Bytes{};
            std::size_t Part = 0;
            std::uint32_t Octet = 0;
            for (const auto Character : Header.Target.Host)
            {
                if (Character == '.')
                {
                    if (Part >= 4 || Octet > 255)
                    {
                        return {};
                    }
                    Ipv4Bytes[Part++] = static_cast<std::uint8_t>(Octet);
                    Octet = 0;
                }
                else if (Character >= '0' && Character <= '9')
                {
                    const auto Digit = static_cast<std::uint32_t>(Character - '0');
                    if (Octet > (255 - Digit) / 10)
                    {
                        return {};
                    }
                    Octet = Octet * 10 + Digit;
                }
                else
                {
                    return {};
                }
            }
            if (Part != 3 || Octet > 255)
            {
                return {};
            }
            Ipv4Bytes[Part] = static_cast<std::uint8_t>(Octet);
            Output.insert(Output.end(), Ipv4Bytes.begin(), Ipv4Bytes.end());
            break;
        }
        case AddressType::Ipv6: {
            boost::system::error_code Ec;
            const auto V6 = Net::ip::make_address_v6(Header.Target.Host, Ec);
            if (!Ec)
            {
                const auto Bytes = V6.to_bytes();
                Output.insert(Output.end(), Bytes.begin(), Bytes.end());
            }
            else
            {
                if (Header.Target.Host.size() != 16)
                {
                    return {};
                }
                Output.insert(Output.end(), Header.Target.Host.begin(), Header.Target.Host.end());
            }
            break;
        }
        case AddressType::Domain: {
            if (Header.Target.Host.empty() || Header.Target.Host.size() > 0xFF)
            {
                return {};
            }
            Output.push_back(static_cast<std::uint8_t>(Header.Target.Host.size()));
            Output.insert(Output.end(), Header.Target.Host.begin(), Header.Target.Host.end());
            break;
        }
        default:
            return {};
        }
        for (std::uint8_t I = 0; I < Metadata.p; ++I)
        {
            Output.push_back(0);
        }
        const auto Hash = detail::Fnv1a32(Output);
        Output.push_back(static_cast<std::uint8_t>((Hash >> 24) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Hash >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Hash >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Hash & 0xFF));
        return Output;
    }

    /**
     * @brief 解析出的请求头元数据
     */
    struct RequestMetaOut
    {
        std::array<std::uint8_t, 16> iv{};
        std::array<std::uint8_t, 16> key{};
        std::uint8_t v{0};
    };

    /**
     * @brief 解析请求头明文并校验 FNV1a
     * @param Data 明文
     * @param Header 输出请求头
     * @param Metadata 输出元数据
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseRequestHeader(
        std::span<const std::uint8_t> Data,
        RequestHeader &Header,
        RequestMetaOut &Metadata) -> Error
    {
        if (Data.size() < 41)
        {
            return Error::NeedMore;
        }
        Header.Version = Data[0];
        if (Header.Version != ProtocolVersion)
        {
            return Error::BadMagic;
        }
        std::memcpy(Metadata.iv.data(), Data.data() + 1, 16);
        std::memcpy(Metadata.key.data(), Data.data() + 17, 16);
        Metadata.v = Data[33];
        Header.opt = Data[34];
        Header.sec = static_cast<Security>(Data[35] & 0x0F);
        Header.reserved = Data[36];
        Header.Cmd = Data[37];
        Header.Target.Port = static_cast<std::uint16_t>(Data[38]) << 8 | Data[39];
        Header.Target.Type = static_cast<AddressType>(Data[40]);
        std::size_t Off = 41;
        switch (Header.Target.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Off < 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> AddressBuffer{};
            std::snprintf(
                AddressBuffer.data(),
                AddressBuffer.size(),
                "%u.%u.%u.%u",
                static_cast<unsigned>(Data[Off]),
                static_cast<unsigned>(Data[Off + 1]),
                static_cast<unsigned>(Data[Off + 2]),
                static_cast<unsigned>(Data[Off + 3]));
            Header.Target.Host = AddressBuffer.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Off < 16)
            {
                return Error::NeedMore;
            }
            Header.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
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
                return Error::BadMessage;
            }
            if (Data.size() - Off < Length)
            {
                return Error::NeedMore;
            }
            Header.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Length);
            Off += Length;
            break;
        }
        default:
            return Error::BadMessage;
        }
        if (Data.size() - Off < 4)
        {
            return Error::NeedMore;
        }
        const auto Hash = detail::Fnv1a32(Data.first(Data.size() - 4));
        const auto Expected = static_cast<std::uint32_t>(Data[Data.size() - 4]) << 24 |
                              static_cast<std::uint32_t>(Data[Data.size() - 3]) << 16 |
                              static_cast<std::uint32_t>(Data[Data.size() - 2]) << 8 |
                              static_cast<std::uint32_t>(Data[Data.size() - 1]);
        if (Hash != Expected)
        {
            return Error::BadAuth;
        }
        return Error::None;
    }

    /**
     * @brief VMess 握手消息
     */
    struct Message
    {
        std::array<std::uint8_t, 16> uuid{};
        std::array<std::uint8_t, 16> RequestNonce{};
        std::array<std::uint8_t, 16> RequestKey{};
        std::uint8_t Cmd{static_cast<std::uint8_t>(Command::Tcp)};
        Address dst;
        std::uint8_t RespHeader{0};
        std::array<std::uint8_t, AuthHeaderLen> AuthId{}; ///< 已验证的加密 AuthID
        std::uint8_t Option{0}; ///< 请求头 option 位（响应数据层对称使用）
    };

    /**
     * @brief VMess 握手序列化器
     */
    class Serializer
    {
    public:
        using RandomSource = std::function<int(std::uint8_t *, int)>;
        /**
         * @brief 构造
         * @param Uuid 客户端 UUID（16 字节）
         */
        explicit Serializer(const std::array<std::uint8_t, 16> &Uuid, RandomSource Source = {})
            : Uuid_(Uuid), Source_(std::move(Source))
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
            const auto CmdKey = CmdKeyFromUuid(Uuid_);
            RequestHeader RequestValue;
            RequestValue.Version = ProtocolVersion;
            RequestValue.Cmd = MessageValue.Cmd;
            RequestValue.opt = MessageValue.Option;
            RequestValue.sec = Security::Aes128Gcm;
            RequestValue.reserved = 0;
            RequestValue.Target = MessageValue.dst;
            const auto Body = BuildRequestHeader(
                RequestValue,
                RequestMeta{MessageValue.RequestNonce, MessageValue.RequestKey, MessageValue.RespHeader, 0});
            if (Body.empty())
            {
                Failed_ = true;
                return;
            }

            std::array<std::uint8_t, 4> RandomBytes{};
            bool Filled = false;
            if (Source_)
            {
                Filled = Preview::Crypto::FillRandom(std::span<std::uint8_t>(RandomBytes), Source_);
            }
            else
            {
                Filled = Preview::Crypto::FillRandom(std::span<std::uint8_t>(RandomBytes));
            }
            if (!Filled)
            {
                Failed_ = true;
                return;
            }
            Wire_ = SealAuthHeader(
                CmdKey,
                AuthHeaderInput{Body, static_cast<std::int64_t>(TimeSec), RandomBytes});
            Ready_ = !Wire_.empty();
            Failed_ = !Ready_;
        }

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param Ec 错误码（成功 = 空）
         * @return 实际写入字节数
         */
        auto Get(Net::mutable_buffer Buffer, std::error_code &Ec) -> std::size_t
        {
            Ec.clear();
            if (!Ready_)
            {
                Ec = make_error_code(Error::IoError);
                return 0;
            }
            const auto Available = Wire_.size() - (std::min)(Offset_, Wire_.size());
            const auto N = (std::min)(Buffer.size(), Available);
            if (N > 0)
            {
                std::memcpy(Buffer.data(), Wire_.data() + Offset_, N);
            }
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
        std::array<std::uint8_t, 16> Uuid_;
        RandomSource Source_;
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
        bool Ready_{false};
        bool Failed_{false};
    };

    /**
     * @brief VMess 握手解析器
     */
    class Parser
    {
    public:
        /**
         * @brief 构造
         * @param Uuid 客户端 UUID
         */
        explicit Parser(const std::array<std::uint8_t, 16> &Uuid) : Uuid_(Uuid)
        {
        }

        /**
         * @brief 增量喂入
         * @param Buffer 输入缓冲区
         * @param Ec 错误码
         * @return 已累积缓冲字节数
         */
        auto Put(Net::const_buffer Buffer, std::error_code &Ec) -> std::size_t
        {
            Ec.clear();
            if (Done_)
            {
                return Buf_.size();
            }
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            Buf_.insert(Buf_.end(), Data.begin(), Data.end());
            if (Buf_.size() < 16 + 18 + 8 + 18)
            {
                Ec = make_error_code(Error::NeedMore);
                return 0;
            }

            const auto CmdKey = CmdKeyFromUuid(Uuid_);
            const auto AuthId = std::span<const std::uint8_t>(Buf_).first(16);
            const auto LenEnc = std::span<const std::uint8_t>(Buf_).subspan(16, 18);
            const auto Nonce8 = std::span<const std::uint8_t>(Buf_).subspan(34, 8);
            const auto LenKey = Kdf(CmdKey, KdfHeaderLenKey, AuthId, Nonce8);
            const auto LenIv = Kdf(CmdKey, KdfHeaderLenIv, AuthId, Nonce8);
            std::array<std::uint8_t, 16> LengthKey{};
            std::memcpy(LengthKey.data(), LenKey.data(), 16);
            std::array<std::uint8_t, 12> LengthIv{};
            std::memcpy(LengthIv.data(), LenIv.data(), 12);
            const auto LenPlain = detail::AesGcmOpen(
                detail::OpenInput{LengthKey, LengthIv, LenEnc, AuthId});
            if (LenPlain.size() != 2)
            {
                Ec = make_error_code(Error::AuthFailed);
                return 0;
            }
            const auto Length = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];
            const auto Total = 16 + 18 + 8 + Length + 16;
            if (Buf_.size() < Total)
            {
                Ec = make_error_code(Error::NeedMore);
                return 0;
            }

            std::vector<std::uint8_t> Body;
            const auto Err = OpenAuthHeader(CmdKey, std::span<const std::uint8_t>(Buf_).first(Total), Body);
            if (Err != Error::None)
            {
                Ec = make_error_code(Err);
                return 0;
            }
            RequestHeader RequestValue{};
            RequestMetaOut Metadata{};
            const auto ParseError = ParseRequestHeader(Body, RequestValue, Metadata);
            if (ParseError != Error::None)
            {
                Ec = make_error_code(ParseError);
                return 0;
            }

            Msg_.uuid = Uuid_;
            std::memcpy(Msg_.AuthId.data(), AuthId.data(), Msg_.AuthId.size());
            Msg_.RequestNonce = Metadata.iv;
            Msg_.RequestKey = Metadata.key;
            Msg_.Cmd = static_cast<std::uint8_t>(RequestValue.Cmd);
            Msg_.dst = RequestValue.Target;
            Msg_.RespHeader = Metadata.v;
            Msg_.Option = RequestValue.opt;
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
        std::array<std::uint8_t, 16> Uuid_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool Done_{false};
    };

} // namespace Preview::Vmess
