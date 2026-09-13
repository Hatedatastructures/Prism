/**
 * @file Codec.hpp
 * @brief SOCKS5 消息编解码（纯函数，零状态）
 * @details 实现 Greeting / MethodReply / Request / Reply 的编解码，
 *          支持增量解析（need_more）与边界校验。
 */

#pragma once

#include <boost/asio/buffer.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Common/Address.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Socks5/Types.hpp>

namespace Preview::Socks5
{

    namespace Net = boost::asio;

    namespace detail
    {
        /**
         * @brief 将四字节 IPv4 地址格式化为点分十进制文本
         * @param Bytes IPv4 地址字节
         * @param Host 输出主机文本
         * @return 格式化成功返回 true
         */
        [[nodiscard]] inline auto FormatIpv4(const std::uint8_t *Bytes, std::string &Host) -> bool
        {
            std::array<char, 16> Buffer{};
            auto *Cursor = Buffer.data();
            for (std::size_t Index = 0; Index < 4; ++Index)
            {
                if (Index != 0)
                {
                    *Cursor++ = '.';
                }
                const auto [End, ErrorCode] = std::to_chars(
                    Cursor, Buffer.data() + Buffer.size(), static_cast<unsigned int>(Bytes[Index]));
                if (ErrorCode != std::errc{})
                {
                    return false;
                }
                Cursor = End;
            }
            Host.assign(Buffer.data(), Cursor);
            return true;
        }
    } // namespace detail

    /**
     * @brief 编码 Greeting（写入复用缓冲）
     * @param GreetingValue 问候（版本 + 方法列表）
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     * @details 覆盖式写入；缓冲容量不足时自动扩容（首次分配后复用）。
     * 接受任意分配器 vector（std::vector / pmr vector 均可）。
     * 方法列表超过 255 项时清空输出，不生成截断的长度字段。
     */
    template <typename Alloc>
    inline auto BuildGreeting(
        const Greeting &GreetingValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (GreetingValue.Methods.size() > 0xFF)
        {
            return;
        }
        Output.reserve(2 + GreetingValue.Methods.size());
        Output.push_back(GreetingValue.Ver);
        Output.push_back(static_cast<std::uint8_t>(GreetingValue.Methods.size()));
        Output.insert(Output.end(), GreetingValue.Methods.begin(), GreetingValue.Methods.end());
    }

    /**
     * @brief 编码 Greeting
     * @param GreetingValue 问候（版本 + 方法列表）
     * @return Greeting 字节：[ver 1B][nmethods 1B][Methods var]
     */
    [[nodiscard]] inline auto BuildGreeting(const Greeting &GreetingValue)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildGreeting(GreetingValue, Output);
        return Output;
    }

    /**
     * @brief 解析 Greeting（增量）
     * @param Data 输入
     * @param Output 输出
     * @param Consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseGreeting(
        std::span<const std::uint8_t> Data,
        Greeting &Output,
        std::size_t &Consumed) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        Output.Ver = Data[0];
        if (Output.Ver != Version)
        {
            return Error::VersionMismatch;
        }
        const auto NMethods = Data[1];
        if (Data.size() < 2 + NMethods)
        {
            return Error::NeedMore;
        }
        Output.Methods.assign(Data.begin() + 2, Data.begin() + 2 + NMethods);
        Consumed = 2 + NMethods;
        return Error::None;
    }

    /**
     * @brief 编码方法选择
     * @param MethodReplyValue 方法选择（版本 + 方法）
     * @return 2 字节回复
     */
    [[nodiscard]] inline auto BuildMethodReply(const MethodReply &MethodReplyValue)
        -> std::array<std::uint8_t, 2>
    {
        return {MethodReplyValue.Ver, static_cast<std::uint8_t>(MethodReplyValue.Method)};
    }

    /**
     * @brief 解析方法选择
     * @param Data 输入
     * @param Output 输出方法选择
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseMethodReply(
        std::span<const std::uint8_t> Data,
        MethodReply &Output) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        Output.Ver = Data[0];
        if (Output.Ver != Version)
        {
            return Error::BadMagic;
        }
        Output.Method = static_cast<AuthMethod>(Data[1]);
        return Error::None;
    }

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param AddressValue 目标地址
     * @param Output 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @note 转发层：统一实现见 Protocol/common::EncodeAddress（行为一致）
     */
    template <typename Alloc>
    inline auto EncodeAddress(
        const Address &AddressValue,
        std::vector<std::uint8_t, Alloc> &Output) -> bool
    {
        return Preview::Protocol::Common::EncodeAddress(AddressValue, Output);
    }

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE）
     * @param AddressValue 目标地址
     * @return 地址字节
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
     * @brief 解析地址（增量）
     * @param Data 输入
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
            if (Data.size() < Off + 4 + 2)
            {
                return Error::NeedMore;
            }
            if (!detail::FormatIpv4(Data.data() + Off, Output.Host))
            {
                return Error::BadMessage;
            }
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < Off + 16 + 2)
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
            const auto Len = Data[Off++];
            if (Len == 0)
            {
                return Error::BadMessage;
            }
            if (Data.size() < Off + Len + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Len);
            Off += Len;
            break;
        }
        default: return Error::BadMessage;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Consumed = Off + 2;
        return Error::None;
    }

    /**
     * @brief 编码请求（写入复用缓冲）
     * @param RequestValue 请求（命令 + 目标地址）
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     * @details 头部 3 字节后直接续写地址，无中间缓冲。
     */
    template <typename Alloc>
    inline auto BuildRequest(
        const Request &RequestValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        Output.reserve(3 + RequestValue.Target.Host.size() + 8);
        Output.push_back(RequestValue.Ver);
        Output.push_back(static_cast<std::uint8_t>(RequestValue.Cmd));
        Output.push_back(RequestValue.Rsv);
        if (!EncodeAddress(RequestValue.Target, Output))
        {
            Output.clear();
            return;
        }
    }

    /**
     * @brief 编码请求
     * @param RequestValue 请求（命令 + 目标地址）
     * @return 请求字节：[ver][cmd][rsv][ATYP][ADDR][PORT]
     */
    [[nodiscard]] inline auto BuildRequest(const Request &RequestValue)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildRequest(RequestValue, Output);
        return Output;
    }

    /**
     * @brief 解析请求（增量）
     * @param Data 输入
     * @param Output 输出请求
     * @param Consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseRequest(
        std::span<const std::uint8_t> Data,
        Request &Output,
        std::size_t &Consumed) -> Error
    {
        if (Data.size() < 4)
        {
            return Error::NeedMore;
        }
        Output.Ver = Data[0];
        if (Output.Ver != Version)
        {
            return Error::BadMagic;
        }
        Output.Cmd = static_cast<Command>(Data[1]);
        if (Output.Cmd != Command::Connect && Output.Cmd != Command::UdpAssociate)
        {
            return Error::NotSupported;
        }
        Output.Rsv = Data[2];
        if (Output.Rsv != 0)
        {
            return Error::BadMessage;
        }
        std::size_t AddrConsumed = 0;
        const auto ErrorCode = ParseAddress(Data.subspan(3), Output.Target, AddrConsumed);
        if (ErrorCode != Error::None)
        {
            return ErrorCode;
        }
        Consumed = 3 + AddrConsumed;
        return Error::None;
    }

    /**
     * @brief 编码响应（写入复用缓冲）
     * @param ReplyValue 响应（状态码 + 绑定地址）
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildReply(
        const Reply &ReplyValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        Output.reserve(3 + ReplyValue.Bind.Host.size() + 8);
        Output.push_back(ReplyValue.Ver);
        Output.push_back(static_cast<std::uint8_t>(ReplyValue.Code));
        Output.push_back(ReplyValue.Rsv);
        if (!EncodeAddress(ReplyValue.Bind, Output))
        {
            Output.clear();
            return;
        }
    }

    /**
     * @brief 编码响应
     * @param ReplyValue 响应（状态码 + 绑定地址）
     * @return 响应字节：[ver][Code][rsv][ATYP][ADDR][PORT]
     */
    [[nodiscard]] inline auto BuildReply(const Reply &ReplyValue)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildReply(ReplyValue, Output);
        return Output;
    }

    /**
     * @brief 解析响应（增量）
     * @param Data 输入
     * @param Output 输出响应
     * @param Consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseReply(
        std::span<const std::uint8_t> Data,
        Reply &Output,
        std::size_t &Consumed) -> Error
    {
        if (Data.size() < 4)
        {
            return Error::NeedMore;
        }
        Output.Ver = Data[0];
        if (Output.Ver != Version)
        {
            return Error::VersionMismatch;
        }
        Output.Code = static_cast<ReplyCode>(Data[1]);
        Output.Rsv = Data[2];
        if (Output.Rsv != 0)
        {
            return Error::BadMessage;
        }
        std::size_t AddrConsumed = 0;
        const auto ErrorCode = ParseAddress(Data.subspan(3), Output.Bind, AddrConsumed);
        if (ErrorCode != Error::None)
        {
            return ErrorCode;
        }
        Consumed = 3 + AddrConsumed;
        return Error::None;
    }

    /**
     * @brief 构造 SOCKS5 UDP 数据报（写入复用缓冲）
     * @param Target 目标地址
     * @param Payload UDP 载荷
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildUdpDatagram(
        const Address &Target,
        std::span<const std::uint8_t> Payload,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        Output.reserve(3 + Target.Host.size() + 8 + Payload.size());
        Output.push_back(0x00);
        Output.push_back(0x00);
        Output.push_back(0x00);
        if (!EncodeAddress(Target, Output))
        {
            Output.clear();
            return;
        }
        Output.insert(Output.end(), Payload.begin(), Payload.end());
    }

    /**
     * @brief 构造 SOCKS5 UDP 数据报（RFC 1928 UDP ASSOCIATE 数据面）
     * @param Target 目标地址
     * @param Payload UDP 载荷
     * @return 数据报字节：[RSV 2B 0x0000][FRAG 1B 0x00][ATYP 1B][ADDR var][PORT 2B BE][payload]
     * @details 头部无长度字段，载荷边界由调用方（一次底层读）约定。
     * @note FRAG 固定 0x00（不支持分片）
     */
    [[nodiscard]] inline auto BuildUdpDatagram(
        const Address &Target,
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildUdpDatagram(Target, Payload, Output);
        return Output;
    }

    /**
     * @brief 解析 SOCKS5 UDP 数据报
     * @param Data 输入数据
     * @param Target 输出目标地址
     * @param Payload 输出载荷（视图指向 Data）
     * @return 错误码；need_more = 数据不足
     * @details 校验 RSV 与 FRAG，地址解析后剩余全部字节即为载荷。
     */
    [[nodiscard]] inline auto ParseUdpDatagram(
        std::span<const std::uint8_t> Data,
        Address &Target,
        std::span<const std::uint8_t> &Payload) -> Error
    {
        if (Data.size() < 3)
        {
            return Error::NeedMore;
        }
        if (Data[0] != 0x00 || Data[1] != 0x00)
        {
            return Error::BadMagic;
        }
        if (Data[2] != 0x00)
        {
            return Error::NotSupported;
        }
        std::size_t Consumed = 0;
        const auto ErrorCode = ParseAddress(Data.subspan(3), Target, Consumed);
        if (ErrorCode != Error::None)
        {
            return ErrorCode;
        }
        Payload = Data.subspan(3 + Consumed);
        return Error::None;
    }

    /**
     * @brief 用户名/密码认证请求（写入复用缓冲）
     * @param User 用户名
     * @param Password 密码
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     * @details 用户名或密码超过 255 字节时清空输出，不生成截断的长度字段。
     */
    template <typename Alloc>
    inline auto BuildUserpass(
        std::string_view User,
        std::string_view Password,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (User.size() > 0xFF || Password.size() > 0xFF)
        {
            return;
        }
        Output.reserve(2 + User.size() + 1 + Password.size());
        Output.push_back(0x01);
        Output.push_back(static_cast<std::uint8_t>(User.size()));
        Output.insert(Output.end(), User.begin(), User.end());
        Output.push_back(static_cast<std::uint8_t>(Password.size()));
        Output.insert(Output.end(), Password.begin(), Password.end());
    }

    /**
     * @brief 用户名/密码认证请求（RFC 1929）
     * @param User 用户名
     * @param Password 密码
     * @return 认证请求字节：[ver 0x01][ulen][uname][plen][passwd]
     */
    [[nodiscard]] inline auto BuildUserpass(std::string_view User, std::string_view Password)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildUserpass(User, Password, Output);
        return Output;
    }

    /**
     * @brief 解析用户名/密码认证响应（1 字节状态）
     * @param Data 输入
     * @return 错误码；0x00 表示认证通过，其余为 bad_auth
     */
    [[nodiscard]] inline auto ParseUserpassReply(std::span<const std::uint8_t> Data) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        if (Data[0] != 0x01)
        {
            return Error::BadMagic;
        }
        if (Data[1] == 0x00)
        {
            return Error::None;
        }
        return Error::BadAuth;
    }

    /**
     * @brief SOCKS5 消息（Beast 风格，供 Serializer/Parser 使用）
     */
    struct Message
    {
        /// 消息类型
        enum class Kind : std::uint8_t
        {
            /// 问候（Greeting）
            Greeting,
            /// 方法选择回复
            MethodReply,
            /// 用户名/密码认证（RFC 1929）
            Userpass,
            /// 请求（CONNECT / UDP_ASSOCIATE）
            Request,
            /// 响应（Reply）
            Reply,
        };

        /// 消息类型
        Kind Type{Kind::Greeting};
        /// 认证方法列表（Greeting）
        std::vector<std::uint8_t> Methods;
        /// 认证方法选择（MethodReply / userpass 状态）
        std::uint8_t Method{0x00};
        /// 命令（Request）
        Command Cmd{Command::Connect};
        /// 响应码（Reply）
        ReplyCode rep{ReplyCode::Success};
        /// 目标 / 绑定地址
        Address addr;
        /// 用户名（userpass）
        std::string username;
        /// 密码（userpass）
        std::string password;
    };

    /**
     * @brief SOCKS5 消息序列化器（对象 → wire，Beast 风格）
     */
    class Serializer
    {
    public:
        /**
         * @brief 重置并绑定消息
         * @param MessageValue 消息（内部持有拷贝，生命周期安全）
         * @details 按消息类型编码为 wire 字节，随后可通过 Get() 增量输出。
         */
        auto Reset(const Message &MessageValue) -> void
        {
            Wire_.clear();
            Offset_ = 0;
            switch (MessageValue.Type)
            {
            case Message::Kind::Greeting: {
                Greeting GreetingValue;
                GreetingValue.Ver = Version;
                GreetingValue.Methods = MessageValue.Methods;
                Wire_ = BuildGreeting(GreetingValue);
                break;
            }
            case Message::Kind::MethodReply: {
                MethodReply MethodReplyValue;
                MethodReplyValue.Ver = Version;
                MethodReplyValue.Method = static_cast<AuthMethod>(MessageValue.Method);
                const auto Wire = BuildMethodReply(MethodReplyValue);
                Wire_.assign(Wire.begin(), Wire.end());
                break;
            }
            case Message::Kind::Userpass: {
                Wire_ = BuildUserpass(MessageValue.username, MessageValue.password);
                break;
            }
            case Message::Kind::Request: {
                Request RequestValue;
                RequestValue.Ver = Version;
                RequestValue.Cmd = MessageValue.Cmd;
                RequestValue.Target = MessageValue.addr;
                Wire_ = BuildRequest(RequestValue);
                break;
            }
            case Message::Kind::Reply: {
                Reply ReplyValue;
                ReplyValue.Ver = Version;
                ReplyValue.Code = MessageValue.rep;
                ReplyValue.Bind = MessageValue.addr;
                Wire_ = BuildReply(ReplyValue);
                break;
            }
            }
        }

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param ErrorCode 错误码输出参数
         * @return 写入字节数
         */
        auto Get(
            Net::mutable_buffer Buffer,
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
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief SOCKS5 消息解析器（wire → 对象，Beast 风格）
     * @details 增量喂入字节流，按 Expect 的消息类型驱动状态机。
     * Put() 返回本次消耗的字节数；不足时返回 need_more（ec 保持空）。
     * 解析完成后通过 Get() 取结果，通过 Remaining() 取未消耗的超读字节。
     */
    class Parser
    {
    public:
        /**
         * @brief 设置期望的消息类型
         * @param Kind 消息类型
         * @details 决定 Put() 内部解析路径（Greeting/MethodReply/userpass/Request/Reply）。
         */
        auto Expect(Message::Kind Kind) -> void
        {
            Expect_ = Kind;
        }

        /**
         * @brief 增量喂入字节
         * @param Buffer 输入数据
         * @param ErrorCode 错误码输出参数
         * @return 本次消耗的字节数（0 = 半帧等待）
         */
        auto Put(
            Net::const_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t
        {
            ErrorCode.clear();
            if (Done_)
            {
                return 0;
            }
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            PrevBufSize_ = Buf_.size();
            Buf_.insert(Buf_.end(), Data.begin(), Data.end());
            std::size_t Consumed = 0;
            Error ParseResult = Error::None;

            switch (Expect_)
            {
            case Message::Kind::Greeting: {
                Greeting GreetingValue;
                ParseResult = ParseGreeting(Buf_, GreetingValue, Consumed);
                if (ParseResult == Error::None)
                {
                    Msg_.Type = Message::Kind::Greeting;
                    Msg_.Methods = std::move(GreetingValue.Methods);
                }
                break;
            }
            case Message::Kind::MethodReply: {
                MethodReply MethodReplyValue;
                ParseResult = ParseMethodReply(Buf_, MethodReplyValue);
                if (ParseResult == Error::None)
                {
                    Msg_.Type = Message::Kind::MethodReply;
                    Msg_.Method = static_cast<std::uint8_t>(MethodReplyValue.Method);
                    Consumed = 2;
                }
                break;
            }
            case Message::Kind::Userpass: {
                // 认证子协商：[ver 0x01][ulen][uname][plen][passwd]
                std::size_t Off = 0;
                if (Buf_.size() < Off + 2)
                {
                    ParseResult = Error::NeedMore;
                    break;
                }
                if (Buf_[0] != 0x01)
                {
                    ParseResult = Error::BadMagic;
                    break;
                }
                const auto ULength = Buf_[1];
                Off = 2;
                if (Buf_.size() < Off + ULength + 1)
                {
                    ParseResult = Error::NeedMore;
                    break;
                }
                Msg_.username.assign(reinterpret_cast<const char *>(Buf_.data() + Off), ULength);
                Off += ULength;
                const auto PLength = Buf_[Off++];
                if (Buf_.size() < Off + PLength)
                {
                    ParseResult = Error::NeedMore;
                    break;
                }
                Msg_.password.assign(reinterpret_cast<const char *>(Buf_.data() + Off), PLength);
                Off += PLength;
                Consumed = Off;
                Msg_.Type = Message::Kind::Userpass;
                break;
            }
            case Message::Kind::Request: {
                Request RequestValue;
                ParseResult = ParseRequest(Buf_, RequestValue, Consumed);
                if (ParseResult == Error::None)
                {
                    Msg_.Type = Message::Kind::Request;
                    Msg_.Cmd = RequestValue.Cmd;
                    Msg_.addr = RequestValue.Target;
                }
                break;
            }
            case Message::Kind::Reply: {
                Reply ReplyValue;
                ParseResult = ParseReply(Buf_, ReplyValue, Consumed);
                if (ParseResult == Error::None)
                {
                    Msg_.Type = Message::Kind::Reply;
                    Msg_.rep = ReplyValue.Code;
                    Msg_.addr = ReplyValue.Bind;
                }
                break;
            }
            }

            if (ParseResult == Error::NeedMore)
            {
                return 0;
            }
            if (ParseResult != Error::None)
            {
                ErrorCode = make_error_code(ParseResult);
                return 0;
            }
            Done_ = true;
            // 返回本次 Put 中构成帧的字节数（跨帧增量语义）
            Consumed_ = Consumed;
            const auto NewBufSize = Buf_.size();
            const auto Incremental = std::min(Consumed, NewBufSize) - PrevBufSize_;
            return Incremental;
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
         * @brief 获取未消耗的超读字节
         * @return 剩余字节（解析完成后调用）
         */
        [[nodiscard]] auto Remaining() const -> std::span<const std::uint8_t>
        {
            if (Buf_.empty() || !Done_)
            {
                return {};
            }
            // 记录 consumed 偏移：Put 成功时保存
            return std::span<const std::uint8_t>(Buf_.data() + Consumed_, Buf_.size() - Consumed_);
        }

        /**
         * @brief 提取未消耗的超读字节（所有权移交）
         * @return 剩余字节
         */
        [[nodiscard]] auto TakeRemaining() -> std::vector<std::uint8_t>
        {
            if (!Done_ || Consumed_ >= Buf_.size())
            {
                return {};
            }
            std::vector<std::uint8_t> Output(
                Buf_.begin() + static_cast<std::ptrdiff_t>(Consumed_),
                Buf_.end());
            Buf_.clear();
            Consumed_ = 0;
            PrevBufSize_ = 0;
            return Output;
        }

        /**
         * @brief 重置
         * @details 清空内部缓冲与解析状态，可复用同一解析器。
         */
        auto Reset() -> void
        {
            Buf_.clear();
            Msg_ = Message{};
            Done_ = false;
            Consumed_ = 0;
            PrevBufSize_ = 0;
        }

    private:
        Message::Kind Expect_{Message::Kind::Greeting};
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        std::size_t Consumed_{0};
        std::size_t PrevBufSize_{0};
        bool Done_{false};
    };

    /**
     * @brief 异步读取并解析一条消息（组合操作）
     * @param Transport 底层传输（Transmission 接口）
     * @param ParserValue 解析器（Expect 已设置）
     * @return 错误码（半帧等待由内部循环处理；EOF = unexpected_eof）
     * @details Beast 风格自由函数：循环 async_read_some → Put，直到解析完成。
     */
    [[nodiscard]] inline auto AsyncRead(
        SharedTransmission Transport,
        Parser &ParserValue) -> Net::awaitable<Error>
    {
        std::array<std::uint8_t, 512> Buffer{};
        while (!ParserValue.IsDone())
        {
            std::error_code ErrorCode;
            auto ByteBuffer = AsBytes(std::span<std::uint8_t>(Buffer));
            const auto N = co_await Transport->async_read_some(ByteBuffer, ErrorCode);
            if (ErrorCode)
            {
                co_return Error::IoError;
            }
            if (N == 0)
            {
                co_return Error::UnexpectedEof;
            }
            if (N > Buffer.size())
            {
                co_return Error::IoError;
            }
            std::error_code ParseError;
            ParserValue.Put(Net::buffer(Buffer.data(), N), ParseError);
            if (ParseError)
            {
                co_return static_cast<Error>(ParseError.value());
            }
        }
        co_return Error::None;
    }

    /**
     * @brief 异步发送一条消息（组合操作）
     * @param Transport 底层传输（Transmission 接口）
     * @param SerializerValue 序列化器（Reset 已设置）
     * @return 错误码
     * @details Beast 风格自由函数：循环 Get → async_write_some，直到输出完成。
     */
    [[nodiscard]] inline auto AsyncWrite(
        SharedTransmission Transport,
        Serializer &SerializerValue)
        -> Net::awaitable<Error>
    {
        std::array<std::uint8_t, 512> Buffer{};
        while (!SerializerValue.IsDone())
        {
            std::error_code ErrorCode;
            const auto N = SerializerValue.Get(
                Net::buffer(Buffer.data(), Buffer.size()),
                ErrorCode);
            if (ErrorCode)
            {
                co_return Error::IoError;
            }
            if (N == 0)
            {
                co_return Error::BadLength;
            }
            std::size_t Done = 0;
            while (Done < N)
            {
                auto View = AsBytes(
                    std::span<const std::uint8_t>(Buffer.data() + Done, N - Done));
                ErrorCode.clear();
                const auto Written = co_await Transport->async_write_some(View, ErrorCode);
                if (ErrorCode)
                {
                    co_return Error::IoError;
                }
                if (Written == 0)
                {
                    co_return Error::BrokenPipe;
                }
                if (Written > N - Done)
                {
                    co_return Error::BrokenPipe;
                }
                Done += Written;
            }
        }
        co_return Error::None;
    }

} // namespace Preview::Socks5
