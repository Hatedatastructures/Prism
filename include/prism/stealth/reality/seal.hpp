/**
 * @file session.hpp
 * @brief Reality 加密传输层
 * @details 实现 TLS 1.3 应用数据记录的加密/解密传输层。
 * 继承 transmission 接口，替代 BoringSSL 的 encrypted 传输层。
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
#include <prism/stealth/reality/constants.hpp>
#include <prism/stealth/reality/keygen.hpp>
#include <boost/asio.hpp>

namespace psm::stealth
{
    namespace net = boost::asio;

    /**
     * @class seal
     * @brief Reality 加密传输层
     * @details 封装 TLS 1.3 应用数据记录的加密/解密。
     * 读取时：从底层传输读取加密的 TLS 记录 → open → 缓冲明文
     * 写入时：将明文 seal 为 TLS 记录 → 写入底层传输
     */
    class seal final : public channel::transport::transmission
    {
    public:
        explicit seal(channel::transport::shared_transmission transport,
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
        auto read_encrypted_record(std::error_code &ec)
            -> net::awaitable<std::size_t>;

        auto write_encrypted_record(std::span<const std::byte> data, std::error_code &ec)
            -> net::awaitable<std::size_t>;

        [[nodiscard]] auto make_nonce(std::span<const std::uint8_t> iv, std::uint64_t sequence) const
            -> std::array<std::uint8_t, tls::AEAD_NONCE_LEN>;

        channel::transport::shared_transmission transport_;
        key_material keys_;

        crypto::aead_context server_encryptor_;
        crypto::aead_context client_decryptor_;

        std::uint64_t read_sequence_ = 0;
        std::uint64_t write_sequence_ = 0;

        memory::vector<std::byte> plaintext_buffer_;
        std::size_t plaintext_offset_ = 0;

        memory::vector<std::byte> record_body_buf_;
        memory::vector<std::uint8_t> decrypted_buf_;
        memory::vector<std::uint8_t> write_plain_buf_;
        memory::vector<std::uint8_t> write_ciphertext_buf_;
    };
} // namespace psm::stealth
