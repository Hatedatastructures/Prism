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
#include <random>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Vmess/Auth.hpp>
#include <preview/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

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
     * @param hdr 请求头
     * @param meta 附加元数据
     * @return 明文字节序列（含 FNV1a 校验）
     */
    [[nodiscard]] inline auto BuildRequestHeader(const RequestHeader &hdr, const RequestMeta &meta)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(64 + hdr.Target.Host.size());
        out.push_back(hdr.Version);
        out.insert(out.end(), meta.iv.begin(), meta.iv.end());
        out.insert(out.end(), meta.key.begin(), meta.key.end());
        out.push_back(meta.v);
        out.push_back(static_cast<std::uint8_t>(hdr.opt));
        out.push_back(static_cast<std::uint8_t>(((meta.p & 0x0F) << 4) | static_cast<std::uint8_t>(hdr.sec)));
        out.push_back(hdr.reserved);
        out.push_back(static_cast<std::uint8_t>(hdr.Cmd));
        out.push_back(static_cast<std::uint8_t>((hdr.Target.Port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.Target.Port & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.Target.Type));
        switch (hdr.Target.Type)
        {
        case AddressType::Ipv4: {
            std::array<std::uint8_t, 4> ip{};
            std::size_t Part = 0;
            std::uint32_t Octet = 0;
            for (const auto b : hdr.Target.Host)
            {
                if (b == '.')
                {
                    if (Part >= 4 || Octet > 255)
                    {
                        return {};
                    }
                    ip[Part++] = static_cast<std::uint8_t>(Octet);
                    Octet = 0;
                }
                else if (b >= '0' && b <= '9')
                {
                    Octet = Octet * 10 + static_cast<std::uint32_t>(b - '0');
                    if (Octet > 255)
                    {
                        return {};
                    }
                }
            }
            if (Part != 3 || Octet > 255)
            {
                return {};
            }
            ip[Part] = static_cast<std::uint8_t>(Octet);
            out.insert(out.end(), ip.begin(), ip.end());
            break;
        }
        case AddressType::Ipv6: {
            boost::system::error_code Ec;
            const auto V6 = boost::asio::ip::make_address_v6(hdr.Target.Host, Ec);
            if (!Ec)
            {
                const auto Bytes = V6.to_bytes();
                out.insert(out.end(), Bytes.begin(), Bytes.end());
            }
            else
            {
                out.insert(out.end(), hdr.Target.Host.begin(), hdr.Target.Host.end());
            }
            break;
        }
        case AddressType::Domain:
        default: {
            out.push_back(static_cast<std::uint8_t>(hdr.Target.Host.size()));
            out.insert(out.end(), hdr.Target.Host.begin(), hdr.Target.Host.end());
            break;
        }
        }
        for (std::uint8_t I = 0; I < meta.p; ++I)
        {
            out.push_back(0);
        }
        const auto Hash = detail::Fnv1a32(out);
        out.push_back(static_cast<std::uint8_t>((Hash >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((Hash >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((Hash >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(Hash & 0xFF));
        return out;
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
     * @param out 输出请求头
     * @param meta 输出元数据
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseRequestHeader(std::span<const std::uint8_t> Data, RequestHeader &out,
                                                   RequestMetaOut &meta) -> Error
    {
        if (Data.size() < 41)
        {
            return Error::NeedMore;
        }
        out.Version = Data[0];
        if (out.Version != ProtocolVersion)
        {
            return Error::BadMagic;
        }
        std::memcpy(meta.iv.data(), Data.data() + 1, 16);
        std::memcpy(meta.key.data(), Data.data() + 17, 16);
        meta.v = Data[33];
        out.opt = Data[34];
        out.sec = static_cast<Security>(Data[35] & 0x0F);
        out.reserved = Data[36];
        out.Cmd = Data[37];
        out.Target.Port = static_cast<std::uint16_t>(Data[38]) << 8 | Data[39];
        out.Target.Type = static_cast<AddressType>(Data[40]);
        std::size_t Off = 41;
        switch (out.Target.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < Off + 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", Data[Off], Data[Off + 1], Data[Off + 2],
                          Data[Off + 3]);
            out.Target.Host = buf.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < Off + 16)
            {
                return Error::NeedMore;
            }
            out.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain:
        default: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Len = Data[Off++];
            if (Data.size() < Off + Len)
            {
                return Error::NeedMore;
            }
            out.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Len);
            Off += Len;
            break;
        }
        }
        if (Data.size() < Off + 4)
        {
            return Error::NeedMore;
        }
        const auto Hash = detail::Fnv1a32(Data.first(Data.size() - 4));
        const auto Expected = static_cast<std::uint32_t>(Data[Data.size() - 4]) << 24 |
                              static_cast<std::uint32_t>(Data[Data.size() - 3]) << 16 |
                              static_cast<std::uint32_t>(Data[Data.size() - 2]) << 8 |
                              static_cast<std::uint32_t>(Data[Data.size() - 1]);
        return Hash == Expected ? Error::None : Error::BadAuth;
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
    };

    /**
     * @brief VMess 握手序列化器
     */
    class Serializer
    {
    public:
        /**
         * @brief 构造
         * @param uuid 客户端 UUID（16 字节）
         */
        explicit Serializer(const std::array<std::uint8_t, 16> &uuid) : Uuid_(uuid)
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param msg 消息
         * @param TimeSec UTC 秒
         */
        auto Reset(const Message &msg, std::uint64_t TimeSec) -> void
        {
            const auto CmdKey = CmdKeyFromUuid(Uuid_);
            RequestHeader hdr;
            hdr.Version = ProtocolVersion;
            hdr.Cmd = msg.Cmd;
            hdr.opt = 0;
            hdr.sec = Security::Aes128Gcm;
            hdr.reserved = 0;
            hdr.Target = msg.dst;
            const auto Body = BuildRequestHeader(hdr, RequestMeta{msg.RequestNonce, msg.RequestKey, msg.RespHeader, 0});

            std::random_device rd;
            std::array<std::uint8_t, 4> random{};
            for (auto &b : random)
            {
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            }
            Wire_ = SealAuthHeader(CmdKey, AuthHeaderInput{Body, static_cast<std::int64_t>(TimeSec), random});
            Offset_ = 0;
        }

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param Ec 错误码（成功 = 空）
         * @return 实际写入字节数
         */
        auto Get(boost::asio::mutable_buffer Buffer, std::error_code &Ec) -> std::size_t
        {
            Ec.clear();
            const auto Available = Wire_.size() - (std::min)(Offset_, Wire_.size());
            const auto N = (std::min)(Buffer.size(), Available);
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
        std::array<std::uint8_t, 16> Uuid_;
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief VMess 握手解析器
     */
    class Parser
    {
    public:
        /**
         * @brief 构造
         * @param uuid 客户端 UUID
         */
        explicit Parser(const std::array<std::uint8_t, 16> &uuid) : Uuid_(uuid)
        {
        }

        /**
         * @brief 增量喂入
         * @param Buffer 输入缓冲区
         * @param Ec 错误码
         * @return 已累积缓冲字节数
         */
        auto Put(boost::asio::const_buffer Buffer, std::error_code &Ec) -> std::size_t
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
            std::array<std::uint8_t, 16> lk{};
            std::memcpy(lk.data(), LenKey.data(), 16);
            std::array<std::uint8_t, 12> liv{};
            std::memcpy(liv.data(), LenIv.data(), 12);
            const auto LenPlain = detail::AesGcmOpen(detail::OpenInput{lk, liv, LenEnc, AuthId});
            if (LenPlain.size() != 2)
            {
                Ec = make_error_code(Error::AuthFailed);
                return 0;
            }
            const auto length = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];
            const auto Total = 16 + 18 + 8 + length + 16;
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
            RequestHeader hdr{};
            RequestMetaOut meta{};
            const auto Perr = ParseRequestHeader(Body, hdr, meta);
            if (Perr != Error::None)
            {
                Ec = make_error_code(Perr);
                return 0;
            }

            Msg_.uuid = Uuid_;
            std::memcpy(Msg_.AuthId.data(), AuthId.data(), Msg_.AuthId.size());
            Msg_.RequestNonce = meta.iv;
            Msg_.RequestKey = meta.key;
            Msg_.Cmd = static_cast<std::uint8_t>(hdr.Cmd);
            Msg_.dst = hdr.Target;
            Msg_.RespHeader = meta.v;
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
