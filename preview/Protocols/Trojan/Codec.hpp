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

#include <algorithm>
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
#include <preview/Foundation/Authenticator.hpp>
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
            std::array<std::uint8_t, 28> Output{};
            unsigned int Len = 0;
            EVP_Digest(Data.data(), Data.size(), Output.data(), &Len, EVP_sha224(), nullptr);
            return Output;
        }

    } // namespace detail

    /**
     * @brief 计算密码凭据（SHA224 hex 56 字符）
     * @param Password 密码
     * @return 56 字符 hex 凭据
     */
    [[nodiscard]] inline auto Credential(std::string_view Password) -> std::string
    {
        const auto Hash = detail::Sha224(AsU8Span(Password));
        std::string Output;
        Output.reserve(CredentialLen);
        static constexpr char Hex[] = "0123456789abcdef";
        for (const auto Byte : Hash)
        {
            Output.push_back(Hex[(Byte >> 4) & 0x0F]);
            Output.push_back(Hex[Byte & 0x0F]);
        }
        return Output;
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param AddressValue 目标地址
     * @param Output 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @note 转发层：统一实现见 Protocol/common::EncodeAddress
     *       （ipv4 越界写修复为非法输入输出 0.0.0.0；ipv6 文本（如 "::1"）
     *       解析为 16 字节二进制，非法/二进制输入原样拷贝）
     */
    template <typename Alloc>
    inline auto EncodeAddress(
        const Address &AddressValue,
        std::vector<std::uint8_t, Alloc> &Output) -> bool
    {
        return Preview::Protocol::Common::EncodeAddress(AddressValue, Output);
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
     * @param AddressValue 目标地址
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
     * @brief 解析地址字节（ATYP + ADDR + PORT 2B BE）
     * @param Data 输入数据
     * @param Output 输出地址
     * @param Consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseAddress(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::size_t &Consumed) -> Error
    {
        if (Data.empty())
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[0]);
        std::size_t Off = 1;
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Off < 4 + 2)
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
            if (Data.size() - Off < 16 + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Data.size() - Off < 1)
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Off++];
            if (Length == 0)
            {
                return Error::BadMessage;
            }
            if (Data.size() - Off < Length + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Length);
            Off += Length;
            break;
        }
        default: return Error::BadMessage;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        Consumed = Off;
        return Error::None;
    }

    /**
     * @brief 构造 Trojan UDP 帧（写入复用缓冲）
     * @param Target 目标地址
     * @param Payload UDP 载荷
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildUdpPkt(
        const Address &Target,
        std::span<const std::uint8_t> Payload,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (Payload.size() > 0xFFFF)
        {
            return;
        }
        Output.reserve(Target.Host.size() + 12 + Payload.size());
        if (!EncodeAddress(Target, Output))
        {
            Output.clear();
            return;
        }
        Output.push_back(static_cast<std::uint8_t>((Payload.size() >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Payload.size() & 0xFF));
        Output.push_back('\r');
        Output.push_back('\n');
        Output.insert(Output.end(), Payload.begin(), Payload.end());
    }

    /**
     * @brief 构造 Trojan UDP 帧（mihomo 兼容）
     * @param Target 目标地址
     * @param Payload UDP 载荷
     * @return 帧字节：[ATYP][ADDR][PORT 2B][LEN 2B BE][CRLF][payload]
     * @details 帧内嵌目标地址与载荷长度，CRLF 分隔头部与载荷
     * （对齐主库 framing::BuildUdpPkt）。
     */
    [[nodiscard]] inline auto BuildUdpPkt(
        const Address &Target,
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildUdpPkt(Target, Payload, Output);
        return Output;
    }

    /**
     * @brief 解析 Trojan UDP 帧
     * @param Data 输入数据（完整帧）
     * @param Target 输出目标地址
     * @param Payload 输出载荷（视图指向 Data）
     * @return 错误码；need_more = 数据不足
     * @details 需先读满地址 + 4 字节头部才能确定载荷长度；
     * 调用方需按长度补读完整帧后再解析。
     */
    [[nodiscard]] inline auto ParseUdpPkt(
        std::span<const std::uint8_t> Data,
        Address &Target,
        std::span<const std::uint8_t> &Payload) -> Error
    {
        std::size_t Consumed = 0;
        const auto ErrorCode = ParseAddress(Data, Target, Consumed);
        if (ErrorCode != Error::None)
        {
            return ErrorCode;
        }
        if (Data.size() - Consumed < 4)
        {
            return Error::NeedMore;
        }
        const auto Length = static_cast<std::size_t>(Data[Consumed]) << 8 | Data[Consumed + 1];
        if (Data[Consumed + 2] != '\r' || Data[Consumed + 3] != '\n')
        {
            return Error::BadMagic;
        }
        const auto PayloadStart = Consumed + 4;
        if (Data.size() - PayloadStart < Length)
        {
            return Error::NeedMore;
        }
        Payload = Data.subspan(PayloadStart, Length);
        return Error::None;
    }

    /**
     * @brief 构造完整请求头（写入复用缓冲）
     * @param Params 请求装配参数
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildRequest(
        const RequestParameters &Params,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (Params.Credential.size() != CredentialLen ||
            (Params.Cmd != Command::Connect && Params.Cmd != Command::UdpAssociate &&
             Params.Cmd != Command::Mux))
        {
            return;
        }
        Output.reserve(CredentialLen + 2 + 1 + Params.Target.Host.size() + 2 + 2);
        Output.insert(Output.end(), Params.Credential.begin(), Params.Credential.end());
        Output.push_back('\r');
        Output.push_back('\n');
        Output.push_back(static_cast<std::uint8_t>(Params.Cmd));
        if (!EncodeAddress(Params.Target, Output))
        {
            Output.clear();
            return;
        }
        Output.push_back('\r');
        Output.push_back('\n');
    }

    /**
     * @brief 构造完整请求头（凭据 + CRLF + 命令地址 + CRLF）
     * @param CredentialValue 56 字符凭据
     * @param Cmd 命令
     * @param Target 目标地址
     * @return 请求头字节
     */
    [[nodiscard]] inline auto BuildRequest(
        std::string_view CredentialValue,
        Command Cmd,
        const Address &Target) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildRequest(RequestParameters{CredentialValue, Cmd, Target}, Output);
        return Output;
    }

    /**
     * @brief 解析 Trojan 请求头（增量）
     * @param Data 输入数据
     * @param Output 输出请求头
     * @param Consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseRequest(
        std::span<const std::uint8_t> Data,
        RequestHeader &Output,
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
        if (Data.size() - Off < 2)
        {
            return Error::NeedMore;
        }
        Output.Cmd = static_cast<Command>(Data[Off++]);
        if (Output.Cmd != Command::Connect && Output.Cmd != Command::UdpAssociate &&
            Output.Cmd != Command::Mux)
        {
            return Error::BadMessage;
        }
        Output.Target.Type = static_cast<AddressType>(Data[Off++]);
        switch (Output.Target.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Off < 4 + 2)
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
            Output.Target.Host = Buffer.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Off < 16 + 2)
            {
                return Error::NeedMore;
            }
            Output.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Data.size() - Off < 1)
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Off++];
            if (Length == 0)
            {
                return Error::BadMessage;
            }
            if (Data.size() - Off < Length + 2)
            {
                return Error::NeedMore;
            }
            Output.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Length);
            Off += Length;
            break;
        }
        default: {
            // 非法 ATYP：拒绝而非按域名宽松解析（与 ParseAddress 一致）
            return Error::BadMessage;
        }
        }
        Output.Target.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() - Off < 2)
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
         * @param Password 密码
         */
        explicit Serializer(std::string_view Password) : Cred_(Credential(Password))
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param MessageValue 消息
         */
        auto Reset(const Message &MessageValue) -> void
        {
            Command CommandValue;
            if (MessageValue.udp)
            {
                CommandValue = Command::UdpAssociate;
            }
            else
            {
                CommandValue = Command::Connect;
            }
            Wire_ = BuildRequest(Cred_, CommandValue, MessageValue.dst);
            Offset_ = 0;
        }

        /**
         * @brief 增量输出
         */
        auto Get(
            boost::asio::mutable_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t
        {
            ErrorCode.clear();
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
         * @param Password 密码
         */
        explicit Parser(std::string_view Password) : Cred_(Credential(Password))
        {
        }

        /**
         * @brief 增量喂入
         * @param Buffer 输入数据
         * @param ErrorCode 错误码输出参数
         * @return 本次消耗的字节数（0 = 半帧等待）
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
            const auto PreviousBufferSize = Buf_.size();
            Buf_.insert(Buf_.end(), Data.begin(), Data.end());
            std::size_t Consumed = 0;
            RequestHeader RequestValue;
            const auto ParseError = ParseRequest(Buf_, RequestValue, Consumed);
            if (ParseError == Error::NeedMore)
            {
                ErrorCode = make_error_code(Error::NeedMore);
                return 0;
            }
            if (ParseError != Error::None)
            {
                ErrorCode = make_error_code(ParseError);
                return 0;
            }
            // 凭据校验（前 56 字节）
            if (Buf_.size() < CredentialLen ||
                !Preview::ConstantTimeEqual(
                    std::string_view(reinterpret_cast<const char *>(Buf_.data()), CredentialLen), Cred_))
            {
                ErrorCode = make_error_code(Error::AuthFailed);
                return 0;
            }
            Msg_.dst = RequestValue.Target;
            Msg_.udp = RequestValue.Cmd == Command::UdpAssociate;
            Msg_.valid = true;
            Valid_ = true;
            Done_ = true;
            return std::min(Consumed, Buf_.size()) - PreviousBufferSize;
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
