/**
 * @file record.hpp
 * @brief TLS 记录帧抽象（RFC 8446 §5.1）
 * @details 统一 TLS 记录帧的读写和序列化，替代各方案中的重复实现。
 * 支持 transport::transmission 和 tcp::socket 两种底层 I/O。
 */
#pragma once

#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <span>


namespace psm::tls
{

    namespace net = boost::asio;

    /**
     * @struct record_header
     * @brief TLS 记录帧头部（5 字节）
     */
    struct record_header
    {
        std::uint8_t content_type{0};
        std::uint16_t version{0x0303};
        std::uint16_t length{0};
    };

    /**
     * @class record
     * @brief TLS 记录帧
     * @details 表示一条完整的 TLS 记录。提供 read/write 协程 I/O，
     * 同时支持 transmission 和 tcp::socket 两种底层。
     */
    class record
    {
    public:
        record() = default;

        // === 访问 ===

        [[nodiscard]] auto header() const noexcept -> const record_header &;
        [[nodiscard]] auto payload() const noexcept -> std::span<const std::byte>;
        [[nodiscard]] auto size() const noexcept -> std::size_t;

        // === 协程 I/O ===

        /** @brief 从 transmission 读取一条 TLS 记录 */
        [[nodiscard]] static auto read(transport::transmission &trans)
            -> net::awaitable<std::pair<fault::code, record>>;

        /** @brief 从 tcp::socket 读取一条 TLS 记录 */
        [[nodiscard]] static auto read(net::ip::tcp::socket &sock)
            -> net::awaitable<std::pair<fault::code, record>>;

        /** @brief 向 transmission 写入此记录 */
        [[nodiscard]] auto write(transport::transmission &trans) const
            -> net::awaitable<fault::code>;

        /** @brief 向 tcp::socket 写入此记录 */
        [[nodiscard]] auto write(net::ip::tcp::socket &sock) const
            -> net::awaitable<fault::code>;

        // === 序列化 ===

        /** @brief 序列化为线路字节 */
        [[nodiscard]] auto serialize() const -> memory::vector<std::byte>;

        // === Builder ===

        class builder;

    private:
        record_header header_{};
        memory::vector<std::byte> payload_;
    };

    /**
     * @class record::builder
     * @brief TLS 记录帧构建器
     */
    class record::builder
    {
    public:
        auto type(std::uint8_t t) noexcept -> builder &;
        auto version(std::uint16_t v) noexcept -> builder &;
        auto payload(std::span<const std::byte> data) -> builder &;
        auto payload_u8(std::span<const std::uint8_t> data) -> builder &;
        [[nodiscard]] auto build() const -> record;

    private:
        record_header header_{};
        memory::vector<std::byte> payload_;
    };

} // namespace psm::tls
