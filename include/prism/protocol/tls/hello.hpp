/**
 * @file hello.hpp
 * @brief TLS ClientHello 解析（RFC 8446 §4.1.2）
 * @details 从 tls::record 提取 ClientHello 字段，提供向后兼容的 to_features()。
 */
#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/tls/types.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace psm::tls
{

    class record;

    /**
     * @class client_hello
     * @brief 解析后的 TLS ClientHello
     */
    class client_hello
    {
    public:
        explicit client_hello() = default;

        // === 字段访问 ===

        /** @brief 获取 SNI 服务器名称 */
        [[nodiscard]] auto sni() const noexcept -> std::string_view;
        /** @brief 获取 Session ID */
        [[nodiscard]] auto session_id() const noexcept -> std::span<const std::uint8_t>;
        /** @brief 检查是否携带 X25519 密钥共享 */
        [[nodiscard]] auto has_x25519() const noexcept -> bool;
        /** @brief 获取 X25519 密钥共享字节 */
        [[nodiscard]] auto x25519_key() const noexcept -> const std::array<std::uint8_t, 32> &;
        /** @brief 获取支持的 TLS 版本列表 */
        [[nodiscard]] auto versions() const noexcept -> std::span<const std::uint16_t>;
        /** @brief 获取客户端随机数 */
        [[nodiscard]] auto random() const noexcept -> const std::array<std::uint8_t, 32> &;
        /** @brief 获取原始 ClientHello 消息字节 */
        [[nodiscard]] auto raw_msg() const noexcept -> std::span<const std::uint8_t>;
        /** @brief 获取原始 TLS 记录字节 */
        [[nodiscard]] auto raw_record() const noexcept -> std::span<const std::byte>;

        // === 解析 ===

        /**
         * @brief 从 TLS 记录解析 ClientHello
         * @param rec TLS 记录帧
         * @return 错误码与解析结果
         */
        [[nodiscard]] static auto from(const record &rec) -> std::pair<fault::code, client_hello>;

        /**
         * @brief 从原始字节解析 ClientHello
         * @param raw 原始消息字节
         * @return 错误码与解析结果
         */
        [[nodiscard]] static auto from_bytes(std::span<const std::uint8_t> raw)
            -> std::pair<fault::code, client_hello>;

        // === 向后兼容 ===

        /**
         * @brief 转换为协议特征结构（向后兼容）
         * @return TLS 握手特征
         */
        [[nodiscard]] auto to_features() const -> protocol::tls::hello_features;

    private:
        memory::string sni_;                                ///< SNI 服务器名称
        memory::vector<std::uint8_t> session_id_;           ///< Session ID
        bool has_x25519_{false};                            ///< 是否携带 X25519 密钥共享
        std::array<std::uint8_t, 32> x25519_key_{};         ///< X25519 密钥共享字节
        memory::vector<std::uint16_t> versions_;            ///< 支持的 TLS 版本列表
        std::array<std::uint8_t, 32> random_{};             ///< 客户端随机数
        memory::vector<std::uint8_t> raw_msg_;              ///< 原始 ClientHello 消息
        memory::vector<std::byte> raw_record_;              ///< 原始 TLS 记录
    };

} // namespace psm::tls
