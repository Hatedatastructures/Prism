/**
 * @file BeastCodec.hpp
 * @brief VLESS 增量消息状态机
 * @details 拥有 Message 值对象、Serializer 和 Parser。无状态 wire
 *          转换由 RequestCodec 与 UdpCodec 提供；Parser 保留 UUID
 *          校验和跨多次输入的半帧状态。
 */

#pragma once

#include <boost/asio/buffer.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Vless/RequestCodec.hpp>
#include <Preview/Protocols/Vless/Types.hpp>

namespace Preview::Vless
{

    namespace Net = boost::asio;

    /**
     * @brief VLESS 帧消息（Beast 风格，供 Serializer/Parser 使用）
     */
    struct Message
    {
        /// 用户 UUID（16 字节）
        std::array<std::uint8_t, UuidLen> uuid{};
        /// 命令（CmdTcp / CmdUdp / CmdMux）
        std::uint8_t cmd{CmdTcp};
        /// 目标地址
        Address dst;
        /// 解析有效
        bool valid{false};
    };

    /**
     * @brief VLESS 帧序列化器（对象到 wire，Beast 风格）
     * @details Reset 生成完整请求头，Get 支持调用方分段取出 wire。
     */
    class Serializer
    {
    public:
        /**
         * @brief 构造序列化器
         * @param Uuid 用户 UUID
         */
        explicit Serializer(const std::array<std::uint8_t, UuidLen> &Uuid) : Uuid_(Uuid)
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param MessageValue 消息
         */
        auto Reset(const Message &MessageValue) -> void
        {
            RequestHeader RequestValue;
            RequestValue.Version = ProtocolVersion;
            RequestValue.Uuid = Uuid_;
            RequestValue.Cmd = static_cast<Command>(MessageValue.cmd);
            RequestValue.Target = MessageValue.dst;
            Wire_ = BuildRequest(RequestValue);
            Offset_ = 0;
        }

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲
         * @param ErrorCode 错误码输出参数
         * @return 本次输出字节数
         */
        auto Get(
            Net::mutable_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t
        {
            ErrorCode.clear();
            const auto Count = std::min(Buffer.size(), Wire_.size() - Offset_);
            std::memcpy(Buffer.data(), Wire_.data() + Offset_, Count);
            Offset_ += Count;
            return Count;
        }

        /**
         * @brief 是否已全部输出
         * @return true 表示全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Offset_ >= Wire_.size();
        }

    private:
        std::array<std::uint8_t, UuidLen> Uuid_;
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief VLESS 帧解析器（wire 到对象，Beast 风格）
     * @details Put 可跨多次调用接收半帧；完成后保留解析结果。
     */
    class Parser
    {
    public:
        /**
         * @brief 构造解析器
         * @param Uuid 期望的用户 UUID（校验用）
         * @param ValidateUuid 是否校验 wire UUID
         */
        explicit Parser(
            const std::array<std::uint8_t, UuidLen> &Uuid,
            const bool ValidateUuid = true)
            : Uuid_(Uuid), ValidateUuid_(ValidateUuid)
        {
        }

        /**
         * @brief 增量喂入
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
                static_cast<const std::uint8_t *>(Buffer.data()),
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
            // UUID 校验
            const std::string_view GotUuid(
                reinterpret_cast<const char *>(RequestValue.Uuid.data()),
                RequestValue.Uuid.size());
            const std::string_view ExpectedUuid(
                reinterpret_cast<const char *>(Uuid_.data()),
                Uuid_.size());
            if (ValidateUuid_ && !Preview::ConstantTimeEqual(GotUuid, ExpectedUuid))
            {
                ErrorCode = make_error_code(Error::BadAuth);
                return 0;
            }
            Msg_.uuid = RequestValue.Uuid;
            Msg_.cmd = static_cast<std::uint8_t>(RequestValue.Cmd);
            Msg_.dst = RequestValue.Target;
            Msg_.valid = true;
            Done_ = true;
            return std::min(Consumed, Buf_.size()) - PreviousBufferSize;
        }

        /**
         * @brief 是否解析完成
         * @return true 表示解析完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Done_;
        }

        /**
         * @brief 获取解析结果
         * @return 解析完成后的消息引用
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return Msg_;
        }

        /**
         * @brief 重置解析器
         * @details 清空内部缓冲与解析状态，可复用同一解析器。
         */
        auto Reset() -> void
        {
            Buf_.clear();
            Msg_ = Message{};
            Done_ = false;
        }

    private:
        std::array<std::uint8_t, UuidLen> Uuid_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool ValidateUuid_{true};
        bool Done_{false};
    };

} // namespace Preview::Vless
