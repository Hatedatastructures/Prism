/**
 * @file BeastCodec.hpp
 * @brief Trojan 增量消息状态机
 * @details 拥有 Message 值对象、Serializer 和 Parser。无状态 wire
 *          转换由 CredentialCodec、AddressCodec、UdpCodec 和
 *          RequestCodec 提供。
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
#include <vector>
#include <string_view>

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Trojan/CredentialCodec.hpp>
#include <Prism/Protocols/Trojan/RequestCodec.hpp>
#include <Prism/Protocols/Trojan/Types.hpp>

namespace Prism::Trojan
{

    /**
     * @brief Trojan 帧消息值对象
     */
    struct Message
    {
        /// 目标地址
        Address Target;
        /// 请求命令
        Command Cmd{Command::Connect};
        /// UDP 模式
        bool Udp{false};
        /// 解析有效
        bool Valid{false};
    };

    /**
     * @brief Trojan 帧序列化器（对象到 wire，Beast 风格）
     * @details Reset 生成完整请求头，Get 支持调用方分段取出 wire。
     */
    class Serializer
    {
    public:
        /**
         * @brief 构造序列化器
         * @param Password 密码
         */
        explicit Serializer(std::string_view Password);

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
            boost::asio::mutable_buffer Buffer,
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
        std::string Cred_;
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief Trojan 帧解析器（wire 到对象，Beast 风格）
     * @details Put 可跨多次调用接收半帧；解析完成后保留解析结果。
     */
    class Parser
    {
    public:
        /**
         * @brief 构造解析器
         * @param Password 密码
         * @param ValidateCredential 是否校验 wire 凭据
         */
        explicit Parser(
            std::string_view Password,
            const bool ValidateCredential = true);

        /**
         * @brief 注入已派生的 wire credential
         * @param CredentialValue 56 字符 SHA-224 hex 凭据
         * @param ValidateCredential 是否执行静态凭据校验
         */
        auto SetCredential(
            std::string_view CredentialValue,
            const bool ValidateCredential) -> void;

        /**
         * @brief 获取当前帧携带的 wire credential
         * @return 认证字段视图；帧未完成时为空
         */
        [[nodiscard]] auto CredentialValue() const noexcept -> std::string_view;

        /**
         * @brief 增量喂入
         * @param Buffer 输入数据
         * @param ErrorCode 错误码输出参数
         * @return 本次消耗的字节数；半帧等待时返回 0
         */
        auto Put(
            boost::asio::const_buffer Buffer,
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
         */
        auto Reset() -> void;

    private:
        std::string Cred_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool ValidateCredential_{true};
        bool Valid_{false};
        bool Done_{false};
    };

} // namespace Prism::Trojan
