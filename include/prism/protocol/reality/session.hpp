/**
 * @file session.hpp
 * @brief Reality 加密传输层
 * @details 实现 TLS 1.3 应用数据记录的加密/解密传输层。
 * 继承 transmission 接口，替代 BoringSSL 的 encrypted 传输层。
 * 上层协议（VLESS handler）通过此传输层进行明文读写，
 * 底层自动处理 TLS 1.3 记录的加密/解密。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <memory>
#include <system_error>
#include <prism/channel/transport/transmission.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/memory/container.hpp>
#include <prism/protocol/reality/constants.hpp>
#include <prism/protocol/reality/keygen.hpp>
#include <boost/asio.hpp>

namespace psm::protocol::reality
{
    namespace net = boost::asio;

    /**
     * @class session
     * @brief Reality 加密传输层
     * @details 封装 TLS 1.3 应用数据记录的加密/解密。
     * 读取时：从底层传输读取加密的 TLS 记录 → 解密 → 缓冲明文
     * 写入时：将明文加密为 TLS 记录 → 写入底层传输
     * @note 使用 AES-128-GCM 加密，sequence number 作为 nonce 的一部分。
     */
    class session final : public channel::transport::transmission
    {
    public:
        /**
         * @brief 构造加密传输层
         * @param transport 底层 TCP 传输（reliable）
         * @param keys TLS 1.3 密钥材料
         */
        explicit session(channel::transport::shared_transmission transport,
                         key_material keys);

        [[nodiscard]] auto is_reliable() const noexcept -> bool override;
        [[nodiscard]] auto executor() const -> executor_type override;

        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        void close() override;
        void cancel() override;

    private:
        /**
         * @brief 从底层传输读取并解密一个 TLS 记录
         */
        auto read_encrypted_record(std::error_code &ec)
            -> net::awaitable<std::size_t>;

        /**
         * @brief 加密并写入一个 TLS 记录
         */
        auto write_encrypted_record(std::span<const std::byte> data, std::error_code &ec)
            -> net::awaitable<std::size_t>;

        /**
         * @brief 构造 AEAD nonce
         */
        auto make_nonce(std::span<const std::uint8_t> iv, std::uint64_t sequence) const
            -> std::array<std::uint8_t, tls::AEAD_NONCE_LEN>;

        channel::transport::shared_transmission transport_;
        key_material keys_;

        // AEAD 上下文
        crypto::aead_context server_encryptor_;
        crypto::aead_context client_decryptor_;

        // 记录序列号
        std::uint64_t read_sequence_ = 0;
        std::uint64_t write_sequence_ = 0;

        // 解密后的明文缓冲区
        memory::vector<std::byte> plaintext_buffer_;
        std::size_t plaintext_offset_ = 0;
    };
} // namespace psm::protocol::reality
