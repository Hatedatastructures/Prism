/**
 * @file RequestCodec.hpp
 * @brief VMess 请求头和请求握手状态机
 * @details 负责请求明文头编解码，以及 Serializer/Parser 的增量握手
 *          状态。认证头 AEAD 与 KDF 位于 AuthCrypto.hpp、AuthKdf.hpp、AuthId.hpp、
 *          AuthHeader.hpp，数据分块位于 ChunkCodec.hpp。
 */

#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <system_error>
#include <vector>

namespace Prism::Vmess
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
    [[nodiscard]] auto BuildRequestHeader(const RequestHeader& Header, const RequestMeta& Metadata)
        -> std::vector<std::uint8_t>;

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
    [[nodiscard]] auto ParseRequestHeader(std::span<const std::uint8_t> Data, RequestHeader& Header,
        RequestMetaOut& Metadata) -> Error;

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
        std::uint8_t Option{0};                           ///< 请求头 option 位（响应数据层对称使用）
    };

    /**
     * @brief VMess 握手序列化器
     */
    class Serializer
    {
    public:
        using RandomSource = std::function<int(std::uint8_t*, int)>;
        /**
         * @brief 构造
         * @param Uuid 客户端 UUID（16 字节）
         */
        explicit Serializer(const std::array<std::uint8_t, 16>& Uuid, RandomSource Source = {});

        /**
         * @brief 重置并绑定消息
         * @param MessageValue 消息
         * @param TimeSec UTC 秒
         */
        auto Reset(const Message& MessageValue, std::uint64_t TimeSec) -> void;

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param Ec 错误码（成功 = 空）
         * @return 实际写入字节数
         */
        auto Get(Net::mutable_buffer Buffer, std::error_code& Ec) -> std::size_t;

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
        explicit Parser(const std::array<std::uint8_t, 16>& Uuid);

        /**
         * @brief 增量喂入
         * @param Buffer 输入缓冲区
         * @param Ec 错误码
         * @return 已累积缓冲字节数
         */
        auto Put(Net::const_buffer Buffer, std::error_code& Ec) -> std::size_t;

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
        [[nodiscard]] auto Get() const -> const Message&
        {
            return Msg_;
        }

        /**
         * @brief 重置解析状态
         */
        auto Reset() -> void;

    private:
        std::array<std::uint8_t, 16> Uuid_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool Done_{false};
    };

} // namespace Prism::Vmess
