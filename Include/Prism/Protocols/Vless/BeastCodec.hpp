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

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Protocols/Vless/Types.hpp>

namespace Prism::Vless
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
        explicit Serializer(const std::array<std::uint8_t, UuidLen> &Uuid);

        /**
         * @brief 重置并绑定消息
         * @param MessageValue 消息
         */
        auto Reset(const Message &MessageValue) -> void;

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲
         * @param ErrorCode 错误码输出参数
         * @return 本次输出字节数
         */
        auto Get(
            Net::mutable_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t;

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
            const bool ValidateUuid = true);

        /**
         * @brief 增量喂入
         * @param Buffer 输入缓冲
         * @param ErrorCode 错误码输出参数
         * @return 本次构成完整消息的输入字节数；半帧时返回 0
         */
        auto Put(
            Net::const_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t;

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
        auto Reset() -> void;

    private:
        std::array<std::uint8_t, UuidLen> Uuid_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool ValidateUuid_{true};
        bool Done_{false};
    };

} // namespace Prism::Vless
