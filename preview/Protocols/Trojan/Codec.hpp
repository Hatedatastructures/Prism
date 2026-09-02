/**
 * @file Codec.hpp
 * @brief Trojan 头部编解码（纯函数，零状态）
 * @details 实现：
 *          - Credential()：SHA224(password) 的 56 字符 hex
 *          - BuildRequest() / ParseRequest()：请求头编解码
 *          - ParseCrlf()：CRLF 校验
 * @note 请求头：[SHA224 56B][CRLF][CMD][ATYP][ADDR][PORT 2B][CRLF]
 */

#pragma once

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Common/Address.hpp>
#include <preview/Protocols/Trojan/Types.hpp>

namespace Preview::Trojan
{

    /**
     * @brief Trojan 请求编码参数
     * @details Credential 和 Target 为借用视图，调用期间必须保持有效。
     */
    struct RequestParameters
    {
        std::string_view Credential;
        Command Cmd;
        const Address &Target;
    };

    namespace detail
    {

        /**
         * @brief SHA-224 摘要
         * @param Data 输入数据
         * @return 28 字节摘要
         */
        [[nodiscard]] inline auto Sha224(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 28>
        {
            std::array<std::uint8_t, 28> out{};
            unsigned int Len = 0;
            EVP_Digest(Data.data(), Data.size(), out.data(), &Len, EVP_sha224(), nullptr);
            return out;
        }

    } // namespace detail

    /**
     * @brief 计算密码凭据（SHA224 hex 56 字符）
     * @param password 密码
     * @return 56 字符 hex 凭据
     */
    [[nodiscard]] inline auto Credential(std::string_view password) -> std::string
    {
        const auto Hash = detail::Sha224(AsU8Span(password));
        std::string out;
        out.reserve(CredentialLen);
        static constexpr char hex[] = "0123456789abcdef";
        for (const auto b : Hash)
        {
            out.push_back(hex[(b >> 4) & 0x0F]);
            out.push_back(hex[b & 0x0F]);
        }
        return out;
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param addr 目标地址
     * @param out 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @note 转发层：统一实现见 Protocol/common::EncodeAddress
     *       （ipv4 越界写修复为非法输入输出 0.0.0.0；ipv6 文本（如 "::1"）
     *       解析为 16 字节二进制，非法/二进制输入原样拷贝）
     */
    template <typename Alloc>
    inline auto EncodeAddress(const Address &addr, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        Preview::Protocol::Common::EncodeAddress(addr, out);
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
     */
    [[nodiscard]] inline auto EncodeAddress(const Address &addr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        EncodeAddress(addr, out);
        return out;
    }

    /**
     * @brief 解析地址字节（ATYP + ADDR + PORT 2B BE）
     * @param Data 输入数据
     * @param out 输出地址
     * @param consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseAddress(std::span<const std::uint8_t> Data, Address &out,
                                            std::size_t &Consumed) -> Error
    {
        if (Data.empty())
        {
            return Error::NeedMore;
        }
        out.Type = static_cast<AddressType>(Data[0]);
        std::size_t Off = 1;
        switch (out.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < Off + 4 + 2)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", Data[Off], Data[Off + 1], Data[Off + 2],
                          Data[Off + 3]);
            out.Host = buf.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < Off + 16 + 2)
            {
                return Error::NeedMore;
            }
            out.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Data.size() < Off + 1)
            {
                return Error::NeedMore;
            }
            const auto Len = Data[Off++];
            if (Data.size() < Off + Len + 2)
            {
                return Error::NeedMore;
            }
            out.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Len);
            Off += Len;
            break;
        }
        default: return Error::BadMessage;
        }
        out.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        Consumed = Off;
        return Error::None;
    }

    /**
     * @brief 构造 Trojan UDP 帧（写入复用缓冲）
     * @param Target 目标地址
     * @param payload UDP 载荷
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildUdpPkt(const Address &Target, std::span<const std::uint8_t> payload,
                              std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.clear();
        out.reserve(Target.Host.size() + 12 + payload.size());
        EncodeAddress(Target, out);
        out.push_back(static_cast<std::uint8_t>((payload.size() >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(payload.size() & 0xFF));
        out.push_back('\r');
        out.push_back('\n');
        out.insert(out.end(), payload.begin(), payload.end());
    }

    /**
     * @brief 构造 Trojan UDP 帧（mihomo 兼容）
     * @param Target 目标地址
     * @param payload UDP 载荷
     * @return 帧字节：[ATYP][ADDR][PORT 2B][LEN 2B BE][CRLF][payload]
     * @details 帧内嵌目标地址与载荷长度，CRLF 分隔头部与载荷
     * （对齐主库 framing::BuildUdpPkt）。
     */
    [[nodiscard]] inline auto BuildUdpPkt(const Address &Target, std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        BuildUdpPkt(Target, payload, out);
        return out;
    }

    /**
     * @brief 解析 Trojan UDP 帧
     * @param Data 输入数据（完整帧）
     * @param Target 输出目标地址
     * @param payload 输出载荷（视图指向 Data）
     * @return 错误码；need_more = 数据不足
     * @details 需先读满地址 + 4 字节头部才能确定载荷长度；
     * 调用方需按长度补读完整帧后再解析。
     */
    [[nodiscard]] inline auto ParseUdpPkt(std::span<const std::uint8_t> Data, Address &Target,
                                            std::span<const std::uint8_t> &payload) -> Error
    {
        std::size_t Consumed = 0;
        auto Err = ParseAddress(Data, Target, Consumed);
        if (Err != Error::None)
        {
            return Err;
        }
        if (Data.size() < Consumed + 4)
        {
            return Error::NeedMore;
        }
        const auto Len = static_cast<std::size_t>(Data[Consumed]) << 8 | Data[Consumed + 1];
        if (Data[Consumed + 2] != '\r' || Data[Consumed + 3] != '\n')
        {
            return Error::BadMagic;
        }
        const auto PayloadStart = Consumed + 4;
        if (Data.size() < PayloadStart + Len)
        {
            return Error::NeedMore;
        }
        payload = Data.subspan(PayloadStart, Len);
        return Error::None;
    }

    /**
     * @brief 构造完整请求头（写入复用缓冲）
     * @param cred 56 字符凭据
     * @param cmd 命令
     * @param Target 目标地址
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildRequest(const RequestParameters &Params,
                              std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.clear();
        out.reserve(CredentialLen + 2 + 1 + Params.Target.Host.size() + 2 + 2);
        out.insert(out.end(), Params.Credential.begin(), Params.Credential.end());
        out.push_back('\r');
        out.push_back('\n');
        out.push_back(static_cast<std::uint8_t>(Params.Cmd));
        EncodeAddress(Params.Target, out);
        out.push_back('\r');
        out.push_back('\n');
    }

    /**
     * @brief 构造完整请求头（凭据 + CRLF + 命令地址 + CRLF）
     * @param cred 56 字符凭据
     * @param cmd 命令
     * @param Target 目标地址
     * @return 请求头字节
     */
    [[nodiscard]] inline auto BuildRequest(std::string_view cred, Command cmd, const Address &Target)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        BuildRequest(RequestParameters{cred, cmd, Target}, out);
        return out;
    }

    /**
     * @brief 解析 Trojan 请求头（增量）
     * @param Data 输入数据
     * @param out 输出请求头
     * @param consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseRequest(std::span<const std::uint8_t> Data, RequestHeader &out,
                                            std::size_t &Consumed) -> Error
    {
        // 凭据 + CRLF = 58 字节
        if (Data.size() < CredentialLen + 2)
        {
            return Error::NeedMore;
        }
        if (Data[CredentialLen] != '\r' || Data[CredentialLen + 1] != '\n')
        {
            return Error::BadMagic;
        }
        std::size_t Off = CredentialLen + 2;
        if (Data.size() < Off + 2)
        {
            return Error::NeedMore;
        }
        out.Cmd = static_cast<Command>(Data[Off++]);
        out.Target.Type = static_cast<AddressType>(Data[Off++]);
        switch (out.Target.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < Off + 4 + 2)
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
            if (Data.size() < Off + 16 + 2)
            {
                return Error::NeedMore;
            }
            out.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Len = Data[Off++];
            if (Data.size() < Off + Len + 2)
            {
                return Error::NeedMore;
            }
            out.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Len);
            Off += Len;
            break;
        }
        default: {
            // 非法 ATYP：拒绝而非按域名宽松解析（与 ParseAddress 一致）
            return Error::BadMessage;
        }
        }
        out.Target.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() < Off + 2)
        {
            return Error::NeedMore;
        }
        if (Data[Off] != '\r' || Data[Off + 1] != '\n')
        {
            return Error::BadMessage;
        }
        Consumed = Off + 2;
        return Error::None;
    }

    /**
     * @brief Trojan 帧消息（Beast 风格，供 Serializer/Parser 使用）
     */
    struct Message
    {
        /// 目标地址
        Address dst;
        /// UDP 模式
        bool udp{false};
        /// 解析有效
        bool valid{false};
    };

    /**
     * @brief Trojan 帧序列化器（对象 → wire，Beast 风格）
     */
    class Serializer
    {
    public:
        /**
         * @brief 构造
         * @param password 密码
         */
        explicit Serializer(std::string_view password) : Cred_(Credential(password))
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param msg 消息
         */
        auto Reset(const Message &msg) -> void
        {
            Command cmd;
            if (msg.udp)
            {
                cmd = Command::UdpAssociate;
            }
            else
            {
                cmd = Command::Connect;
            }
            Wire_ = BuildRequest(Cred_, cmd, msg.dst);
            Offset_ = 0;
        }

        /**
         * @brief 增量输出
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
        std::string Cred_;
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief Trojan 帧解析器（wire → 对象，Beast 风格）
     */
    class Parser
    {
    public:
        /**
         * @brief 构造
         * @param password 密码
         */
        explicit Parser(std::string_view password) : Cred_(Credential(password))
        {
        }

        /**
         * @brief 增量喂入
         */
        auto Put(boost::asio::const_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            Buf_.insert(Buf_.end(), Data.begin(), Data.end());
            std::size_t Consumed = 0;
            RequestHeader req;
            const auto Err = ParseRequest(Buf_, req, Consumed);
            if (Err == Error::NeedMore)
            {
                ec = make_error_code(Error::NeedMore);
                return 0;
            }
            if (Err != Error::None)
            {
                ec = make_error_code(Err);
                return 0;
            }
            // 凭据校验（前 56 字节）
            if (Buf_.size() < CredentialLen || std::memcmp(Buf_.data(), Cred_.data(), CredentialLen) != 0)
            {
                ec = make_error_code(Error::AuthFailed);
                return 0;
            }
            Msg_.dst = req.Target;
            Msg_.udp = req.Cmd == Command::UdpAssociate;
            Msg_.valid = true;
            Valid_ = true;
            Done_ = true;
            return Consumed;
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
         * @return 消息引用（解析完成后调用）
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return Msg_;
        }

        /**
         * @brief 重置
         */
        auto Reset() -> void
        {
            Buf_.clear();
            Msg_ = Message{};
            Valid_ = false;
            Done_ = false;
        }

    private:
        std::string Cred_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool Valid_{false};
        bool Done_{false};
    };
} // namespace Preview::Trojan
