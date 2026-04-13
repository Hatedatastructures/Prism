/**
 * @file session.cpp
 * @brief Reality 加密传输层实现
 * @details 实现 TLS 1.3 应用数据记录的加密/解密。
 * 读操作：读取 TLS 记录 → 解密 → 缓冲 → 按需返回
 * 写操作：加密为 TLS 记录 → 写入底层传输
 */

#include <prism/protocol/reality/session.hpp>
#include <prism/trace.hpp>
#include <cstring>
#include <algorithm>

namespace psm::protocol::reality
{
    constexpr std::string_view SessTag = "[Reality.Session]";

    session::session(channel::transport::shared_transmission transport, key_material keys)
        : transport_(std::move(transport)),
          keys_(std::move(keys)),
          server_encryptor_(crypto::aead_cipher::aes_128_gcm, keys_.server_app_key),
          client_decryptor_(crypto::aead_cipher::aes_128_gcm, keys_.client_app_key)
    {
    }

    auto session::is_reliable() const noexcept -> bool
    {
        return transport_ && transport_->is_reliable();
    }

    auto session::executor() const -> executor_type
    {
        if (!transport_)
        {
            trace::error("{} executor called with null transport", SessTag);
            throw std::runtime_error("session::executor called with null transport");
        }
        return transport_->executor();
    }

    auto session::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        // 如果缓冲区有剩余数据，直接返回
        if (plaintext_offset_ < plaintext_buffer_.size())
        {
            const auto remaining = plaintext_buffer_.size() - plaintext_offset_;
            const auto to_copy = std::min(remaining, buffer.size());
            std::memcpy(buffer.data(), plaintext_buffer_.data() + plaintext_offset_, to_copy);
            plaintext_offset_ += to_copy;

            // 如果全部消费完，清空缓冲区
            if (plaintext_offset_ >= plaintext_buffer_.size())
            {
                plaintext_buffer_.clear();
                plaintext_offset_ = 0;
            }
            co_return to_copy;
        }

        // 缓冲区为空，读取新的加密记录
        const auto n = co_await read_encrypted_record(ec);
        if (ec || n == 0)
        {
            co_return 0;
        }

        // 重新尝试从缓冲区返回数据
        if (plaintext_offset_ < plaintext_buffer_.size())
        {
            const auto remaining = plaintext_buffer_.size() - plaintext_offset_;
            const auto to_copy = std::min(remaining, buffer.size());
            std::memcpy(buffer.data(), plaintext_buffer_.data() + plaintext_offset_, to_copy);
            plaintext_offset_ += to_copy;

            if (plaintext_offset_ >= plaintext_buffer_.size())
            {
                plaintext_buffer_.clear();
                plaintext_offset_ = 0;
            }
            co_return to_copy;
        }

        co_return 0;
    }

    auto session::async_write_some(const std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();
        const auto written = co_await write_encrypted_record(buffer, ec);
        co_return written;
    }

    void session::close()
    {
        if (transport_)
        {
            transport_->close();
        }
    }

    void session::cancel()
    {
        if (transport_)
        {
            transport_->cancel();
        }
    }

    // ========================================================================
    // TLS 记录加密/解密
    // ========================================================================

    auto session::make_nonce(const std::span<const std::uint8_t> iv, const std::uint64_t sequence) const
        -> std::array<std::uint8_t, tls::AEAD_NONCE_LEN>
    {
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> nonce{};
        std::memcpy(nonce.data(), iv.data(), tls::AEAD_NONCE_LEN);

        // XOR sequence 的大端表示
        for (int i = 0; i < 8; ++i)
        {
            nonce[tls::AEAD_NONCE_LEN - 1 - i] ^= static_cast<std::uint8_t>((sequence >> (8 * i)) & 0xFF);
        }
        return nonce;
    }

    auto session::read_encrypted_record(std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        // 读取 TLS record header (5 bytes)
        std::array<std::byte, tls::RECORD_HEADER_LEN> header{};
        std::size_t header_read = 0;
        while (header_read < tls::RECORD_HEADER_LEN)
        {
            const auto n = co_await transport_->async_read_some(
                std::span<std::byte>(header.data() + header_read, tls::RECORD_HEADER_LEN - header_read), ec);
            if (ec || n == 0)
            {
                co_return 0;
            }
            header_read += n;
        }

        // 解析 record header
        const auto *raw = reinterpret_cast<const std::uint8_t *>(header.data());
        const auto content_type = raw[0];
        const auto record_len = (static_cast<std::size_t>(raw[3]) << 8) | static_cast<std::size_t>(raw[4]);

        // 读取 record body
        memory::vector<std::byte> record_body(record_len);
        std::size_t body_read = 0;
        while (body_read < record_len)
        {
            auto buf_span = std::span<std::byte>(record_body.data() + body_read, record_len - body_read);
            const auto n = co_await transport_->async_read_some(buf_span, ec);
            if (ec || n == 0)
            {
                co_return 0;
            }
            body_read += n;
        }

        // 处理不同 content_type
        if (content_type == tls::CONTENT_TYPE_ALERT)
        {
            // Alert 记录，可能是 close_notify
            trace::debug("{} received TLS alert record", SessTag);
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        if (content_type != tls::CONTENT_TYPE_APPLICATION_DATA)
        {
            trace::warn("{} unexpected content type: 0x{:02x}", SessTag, content_type);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 解密
        if (record_len < tls::AEAD_TAG_LEN)
        {
            trace::error("{} record too short for AEAD tag", SessTag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 构造 nonce
        const auto nonce = make_nonce(keys_.client_app_iv, read_sequence_);
        ++read_sequence_;

        // additional_data = record header
        std::array<std::uint8_t, tls::RECORD_HEADER_LEN> ad{};
        ad[0] = tls::CONTENT_TYPE_APPLICATION_DATA;
        ad[1] = 0x03;
        ad[2] = 0x03;
        ad[3] = raw[3];
        ad[4] = raw[4];

        // 解密（显式 nonce）
        const auto ciphertext = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(record_body.data()), record_len);
        const auto plaintext_len = record_len - tls::AEAD_TAG_LEN;

        memory::vector<std::uint8_t> decrypted(plaintext_len);
        const auto nonce_span = std::span<const std::uint8_t>{nonce.data(), nonce.size()};
        const auto ad_span = std::span<const std::uint8_t>{ad.data(), ad.size()};
        const auto dec_ec = client_decryptor_.open(decrypted, ciphertext, nonce_span, ad_span);
        if (fault::failed(dec_ec))
        {
            trace::error("{} AEAD decrypt failed", SessTag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 去掉末尾的 content_type 和 padding
        // TLS 1.3: plaintext = [data][content_type][zeros...]
        // 从末尾找 content_type（最后一个非零字节）
        std::size_t data_end = decrypted.size();
        while (data_end > 0 && decrypted[data_end - 1] == 0x00)
        {
            --data_end;
        }
        if (data_end > 0)
        {
            --data_end; // 去掉 content_type 字节本身
        }

        // 存入明文缓冲区
        plaintext_buffer_.clear();
        plaintext_offset_ = 0;
        plaintext_buffer_.reserve(data_end);
        for (std::size_t i = 0; i < data_end; ++i)
        {
            plaintext_buffer_.push_back(static_cast<std::byte>(decrypted[i]));
        }

        co_return plaintext_buffer_.size();
    }

    auto session::write_encrypted_record(const std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (data.empty())
        {
            ec.clear();
            co_return 0;
        }

        // 构造 TLS 1.3 内部明文: data + content_type(0x17)
        memory::vector<std::uint8_t> inner;
        inner.reserve(data.size() + 1);
        inner.insert(inner.end(),
                     reinterpret_cast<const std::uint8_t *>(data.data()),
                     reinterpret_cast<const std::uint8_t *>(data.data()) + data.size());
        inner.push_back(tls::CONTENT_TYPE_APPLICATION_DATA);

        // 构造 nonce
        const auto nonce = make_nonce(keys_.server_app_iv, write_sequence_);
        ++write_sequence_;

        // additional_data = record header (预计算长度)
        const auto encrypted_len = inner.size() + tls::AEAD_TAG_LEN;
        std::array<std::uint8_t, tls::RECORD_HEADER_LEN> ad{};
        ad[0] = tls::CONTENT_TYPE_APPLICATION_DATA;
        ad[1] = 0x03;
        ad[2] = 0x03;
        ad[3] = static_cast<std::uint8_t>((encrypted_len >> 8) & 0xFF);
        ad[4] = static_cast<std::uint8_t>(encrypted_len & 0xFF);

        // 加密（显式 nonce）
        memory::vector<std::uint8_t> ciphertext(encrypted_len);
        const auto nonce_span = std::span<const std::uint8_t>{nonce.data(), nonce.size()};
        const auto ad_span = std::span<const std::uint8_t>{ad.data(), ad.size()};
        const auto enc_ec = server_encryptor_.seal(ciphertext, inner, nonce_span, ad_span);
        if (fault::failed(enc_ec))
        {
            trace::error("{} AEAD encrypt failed", SessTag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 构造 TLS 记录
        memory::vector<std::byte> record;
        record.reserve(tls::RECORD_HEADER_LEN + encrypted_len);
        // Record header
        record.push_back(static_cast<std::byte>(tls::CONTENT_TYPE_APPLICATION_DATA));
        record.push_back(static_cast<std::byte>(0x03));
        record.push_back(static_cast<std::byte>(0x03));
        record.push_back(static_cast<std::byte>((encrypted_len >> 8) & 0xFF));
        record.push_back(static_cast<std::byte>(encrypted_len & 0xFF));
        // Record body
        record.insert(record.end(),
                      reinterpret_cast<const std::byte *>(ciphertext.data()),
                      reinterpret_cast<const std::byte *>(ciphertext.data() + ciphertext.size()));

        // 写入
        const auto written = co_await transport_->async_write(record, ec);
        if (ec)
        {
            co_return 0;
        }

        co_return data.size();
    }
} // namespace psm::protocol::reality
