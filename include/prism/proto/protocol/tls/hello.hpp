/**
 * @file hello.hpp
 * @brief TLS ClientHello 解析（RFC 8446 §4.1.2）
 * @details 从 tls::record 提取 ClientHello 字段，提供向后兼容的 to_features()。
 */
#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/proto/protocol/tls/types.hpp>

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

        [[nodiscard]] auto sni() const noexcept -> std::string_view;
        [[nodiscard]] auto session_id() const noexcept -> std::span<const std::uint8_t>;
        [[nodiscard]] auto has_x25519() const noexcept -> bool;
        [[nodiscard]] auto x25519_key() const noexcept -> const std::array<std::uint8_t, 32> &;
        [[nodiscard]] auto versions() const noexcept -> std::span<const std::uint16_t>;
        [[nodiscard]] auto random() const noexcept -> const std::array<std::uint8_t, 32> &;
        [[nodiscard]] auto raw_msg() const noexcept -> std::span<const std::uint8_t>;
        [[nodiscard]] auto raw_record() const noexcept -> std::span<const std::byte>;

        // === 解析 ===

        [[nodiscard]] static auto from(const record &rec)
            -> std::pair<fault::code, client_hello>;

        [[nodiscard]] static auto from_bytes(std::span<const std::uint8_t> raw)
            -> std::pair<fault::code, client_hello>;

        // === 向后兼容 ===

        [[nodiscard]] auto to_features() const -> protocol::tls::hello_features;

    private:
        memory::string sni_;
        memory::vector<std::uint8_t> session_id_;
        bool has_x25519_{false};
        std::array<std::uint8_t, 32> x25519_key_{};
        memory::vector<std::uint16_t> versions_;
        std::array<std::uint8_t, 32> random_{};
        memory::vector<std::uint8_t> raw_msg_;
        memory::vector<std::byte> raw_record_;
    };

} // namespace psm::tls
