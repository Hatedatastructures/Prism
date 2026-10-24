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

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Socks5/AuthCodec.hpp>
#include <Prism/Protocols/Socks5/MessageCodec.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>

namespace Prism::Socks5
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
        auto Reset(const Message &MessageValue) -> void;

        /**
         * @brief 增量输出一段 wire
         * @param Buffer 输出缓冲区
         * @param ErrorCode 错误码输出参数
         * @return 本次输出字节数
         */
        auto Get(
            Net::mutable_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t;

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
        auto Expect(Message::Kind Kind) -> void;

        /**
         * @brief 增量喂入字节
         * @param Buffer 输入缓冲
         * @param ErrorCode 错误码输出参数
         * @return 本次构成完整消息的输入字节数；半帧时返回 0
         */
        auto Put(
            Net::const_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t;

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
        [[nodiscard]] auto Remaining() const -> std::span<const std::uint8_t>;

        /**
         * @brief 提取未消耗的超读字节
         */
        [[nodiscard]] auto TakeRemaining() -> std::vector<std::uint8_t>;

        /**
         * @brief 清空内部缓冲并复用解析器
         */
        auto Reset() -> void;

    private:
        Message::Kind Expect_{Message::Kind::Greeting};
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        std::size_t Consumed_{0};
        std::size_t PrevBufSize_{0};
        bool Done_{false};
    };

} // namespace Prism::Socks5
