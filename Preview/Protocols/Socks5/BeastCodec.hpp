/**
 * @file BeastCodec.hpp
 * @brief SOCKS5 增量消息状态机
 * @details 拥有 Message 值对象、Serializer 和 Parser。wire 字段的无状态
 *          编解码由 MessageCodec 与 AuthCodec 提供，本头只负责状态保存、
 *          partial read/write 和超读提取。
 */

#pragma once

#include <boost/asio/buffer.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Socks5/AuthCodec.hpp>
#include <Preview/Protocols/Socks5/MessageCodec.hpp>
#include <Preview/Protocols/Socks5/Types.hpp>

namespace Preview::Socks5
{

    namespace Net = boost::asio;

    /**
     * @brief SOCKS5 消息值对象
     */
    struct Message
    {
        /// 消息类型
        enum class Kind : std::uint8_t
        {
            /// 问候
            Greeting,
            /// 方法选择回复
            MethodReply,
            /// 用户名/密码认证
            Userpass,
            /// CONNECT / UDP_ASSOCIATE 请求
            Request,
            /// 响应
            Reply,
        };

        Kind Type{Kind::Greeting};
        std::vector<std::uint8_t> Methods;
        std::uint8_t Method{0x00};
        Command Cmd{Command::Connect};
        ReplyCode Code{ReplyCode::Success};
        Address AddressValue;
        std::string Username;
        std::string Password;
    };

    /**
     * @brief SOCKS5 消息序列化器
     * @details Reset 生成完整 wire，Get 可被调用方以任意缓冲区大小增量
     *          取出；状态只在本对象内保存。
     */
    class Serializer
    {
    public:
        /**
         * @brief 重置并绑定消息
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
            case Message::Kind::Userpass:
                Wire_ = BuildUserpass(MessageValue.Username, MessageValue.Password);
                break;
            case Message::Kind::Request: {
                Request RequestValue;
                RequestValue.Ver = Version;
                RequestValue.Cmd = MessageValue.Cmd;
                RequestValue.Target = MessageValue.AddressValue;
                Wire_ = BuildRequest(RequestValue);
                break;
            }
            case Message::Kind::Reply: {
                Reply ReplyValue;
                ReplyValue.Ver = Version;
                ReplyValue.Code = MessageValue.Code;
                ReplyValue.Bind = MessageValue.AddressValue;
                Wire_ = BuildReply(ReplyValue);
                break;
            }
            }
        }

        /**
         * @brief 增量输出一段 wire
         * @param Buffer 输出缓冲区
         * @param ErrorCode 错误码输出参数
         * @return 本次输出字节数
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
         * @brief 判断 wire 是否全部输出
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
     * @brief SOCKS5 增量消息解析器
     * @details Put 可跨多次调用接收半帧；解析完成后 Remaining/TakeRemaining
     *          提取同一底层读取中的超读字节。
     */
    class Parser
    {
    public:
        /**
         * @brief 设置期望的消息类型
         */
        auto Expect(Message::Kind Kind) -> void
        {
            Expect_ = Kind;
        }

        /**
         * @brief 增量喂入字节
         * @param Buffer 输入缓冲
         * @param ErrorCode 错误码输出参数
         * @return 本次构成完整消息的输入字节数；半帧时返回 0
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
            const auto Data = std::span<const std::uint8_t>(
                static_cast<const std::uint8_t *>(Buffer.data()), Buffer.size());
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
                Msg_.Username.assign(reinterpret_cast<const char *>(Buf_.data() + Off), ULength);
                Off += ULength;
                const auto PLength = Buf_[Off++];
                if (Buf_.size() < Off + PLength)
                {
                    ParseResult = Error::NeedMore;
                    break;
                }
                Msg_.Password.assign(reinterpret_cast<const char *>(Buf_.data() + Off), PLength);
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
                    Msg_.AddressValue = RequestValue.Target;
                }
                break;
            }
            case Message::Kind::Reply: {
                Reply ReplyValue;
                ParseResult = ParseReply(Buf_, ReplyValue, Consumed);
                if (ParseResult == Error::None)
                {
                    Msg_.Type = Message::Kind::Reply;
                    Msg_.Code = ReplyValue.Code;
                    Msg_.AddressValue = ReplyValue.Bind;
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
            Consumed_ = Consumed;
            const auto NewBufSize = Buf_.size();
            const auto Incremental = std::min(Consumed, NewBufSize) - PrevBufSize_;
            return Incremental;
        }

        /**
         * @brief 判断解析是否完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Done_;
        }

        /**
         * @brief 获取解析结果
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return Msg_;
        }

        /**
         * @brief 获取未消耗的超读字节视图
         */
        [[nodiscard]] auto Remaining() const -> std::span<const std::uint8_t>
        {
            if (Buf_.empty() || !Done_)
            {
                return {};
            }
            return std::span<const std::uint8_t>(Buf_.data() + Consumed_, Buf_.size() - Consumed_);
        }

        /**
         * @brief 提取未消耗的超读字节
         */
        [[nodiscard]] auto TakeRemaining() -> std::vector<std::uint8_t>
        {
            if (!Done_ || Consumed_ >= Buf_.size())
            {
                return {};
            }
            std::vector<std::uint8_t> Output(
                Buf_.begin() + static_cast<std::ptrdiff_t>(Consumed_), Buf_.end());
            Buf_.clear();
            Consumed_ = 0;
            PrevBufSize_ = 0;
            return Output;
        }

        /**
         * @brief 清空内部缓冲并复用解析器
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

} // namespace Preview::Socks5
