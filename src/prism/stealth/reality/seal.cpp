#include <prism/stealth/reality/seal.hpp>
#include <prism/stealth/common.hpp>
#include <prism/trace.hpp>
#include <prism/transport/transmission.hpp>
#include <cstring>
#include <algorithm>

namespace psm::stealth::reality
{
    using namespace psm::protocol;

    constexpr std::string_view SessTag = "[Stealth.Session]";

    seal::seal(transport::shared_transmission transport, key_material keys)
        : transport_(std::move(transport)),
          keys_(std::move(keys)),
          server_encryptor_(crypto::aead_cipher::aes_128_gcm, keys_.server_app_key),
          client_decryptor_(crypto::aead_cipher::aes_128_gcm, keys_.client_app_key)
    {
    }

    auto seal::executor() const
        -> executor_type
    {
        if (!transport_)
        {
            trace::error("{} executor called with null transport", SessTag);
            return net::io_context{}.get_executor();
        }
        return transport_->executor();
    }

    auto seal::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        // 缓冲区还有剩余数据，直接切片返回
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

        // 缓冲区空了，读取新的加密 TLS 记录
        const auto n = co_await read_encrypted_record(ec);
        if (ec || n == 0)
            co_return 0;

        // 解密后数据已填入缓冲区
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

    auto seal::async_write_some(const std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();
        // TLS 1.3 最大明文 2^14 = 16384，减去 content_type 字节 = 16383
        constexpr std::size_t max_app_data = 16383;
        const auto chunk = buffer.size() > max_app_data
            ? std::span<const std::byte>(buffer.data(), max_app_data)
            : buffer;
        const auto written = co_await write_encrypted_record(chunk, ec);
        co_return written;
    }

    void seal::close()
    {
        if (transport_)
            transport_->close();
    }

    void seal::cancel()
    {
        if (transport_)
            transport_->cancel();
    }

    auto seal::read_encrypted_record(std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        // 1. 读取 TLS 记录头
        std::array<std::byte, tls::RECORD_HEADER_LEN> header{};
        std::size_t header_read = 0;
        while (header_read < tls::RECORD_HEADER_LEN)
        {
            const auto n = co_await transport_->async_read_some(
                std::span<std::byte>(header.data() + header_read, tls::RECORD_HEADER_LEN - header_read), ec);
            if (ec || n == 0)
                co_return 0;
            header_read += n;
        }

        // safe: casting byte array to uint8_t to parse TLS record header fields
        const auto *raw = reinterpret_cast<const std::uint8_t *>(header.data());
        const auto content_type = raw[0];
        const auto record_len = (static_cast<std::size_t>(raw[3]) << 8) | static_cast<std::size_t>(raw[4]);

        // 2. 读取记录体
        record_body_buf_.resize(record_len);
        auto &record_body = record_body_buf_;
        std::size_t body_read = 0;
        while (body_read < record_len)
        {
            auto buf_span = std::span<std::byte>(record_body.data() + body_read, record_len - body_read);
            const auto n = co_await transport_->async_read_some(buf_span, ec);
            if (ec || n == 0)
                co_return 0;
            body_read += n;
        }

        // 3. 处理内容类型
        if (content_type == tls::CONTENT_TYPE_ALERT)
        {
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

        if (record_len < tls::AEAD_TAG_LEN)
        {
            trace::error("{} record too short for AEAD tag", SessTag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 4. 序列号溢出检测
        if (read_sequence_ >= UINT64_MAX - 1)
        {
            trace::error("{} read sequence number overflow: {}", SessTag, read_sequence_);
            ec = fault::code::crypto_error;
            co_return 0;
        }

        // 5. AEAD 解密
        const auto nonce = common::make_aead_nonce(
            std::span<const std::uint8_t>(keys_.client_app_iv.data(), keys_.client_app_iv.size()),
            read_sequence_);
        ++read_sequence_;

        const auto ad = common::make_record_ad((static_cast<std::uint16_t>(raw[3]) << 8) | raw[4]);

        // safe: casting byte vector to uint8_t span for AEAD ciphertext input
        const auto ciphertext = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(record_body.data()), record_len);
        const auto plaintext_len = record_len - tls::AEAD_TAG_LEN;

        decrypted_buf_.resize(plaintext_len);
        auto &decrypted = decrypted_buf_;
        const auto nonce_span = std::span<const std::uint8_t>{nonce.data(), nonce.size()};
        const auto ad_span = std::span<const std::uint8_t>{ad.data(), ad.size()};
        const auto dec_ec = client_decryptor_.open(decrypted, ciphertext, nonce_span, ad_span);
        if (!first_read_logged_)
        {
            first_read_logged_ = true;
            trace::debug("{} first decrypt: seq={}, cipher_len={}",
                        SessTag, read_sequence_ - 1, ciphertext.size());
        }
        if (fault::failed(dec_ec))
        {
            trace::error("{} AEAD decrypt failed", SessTag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 5. TLS 1.3 内部明文格式：去掉零填充和 content_type
        std::size_t data_end = decrypted.size();
        while (data_end > 0 && decrypted[data_end - 1] == 0x00)
            --data_end;
        if (data_end > 0)
            --data_end;

        // 6. 存入缓冲区
        plaintext_buffer_.clear();
        plaintext_offset_ = 0;
        plaintext_buffer_.resize(data_end);
        if (data_end > 0)
            std::memcpy(plaintext_buffer_.data(), decrypted.data(), data_end);

        co_return plaintext_buffer_.size();
    }

    auto seal::write_encrypted_record(const std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (data.empty())
        {
            ec.clear();
            co_return 0;
        }

        // TLS 1.3 内部明文
        write_plain_buf_.resize(data.size() + 1);
        std::memcpy(write_plain_buf_.data(), data.data(), data.size());
        write_plain_buf_[data.size()] = tls::CONTENT_TYPE_APPLICATION_DATA;
        auto &inner = write_plain_buf_;

        // 序列号溢出检测
        if (write_sequence_ >= UINT64_MAX - 1)
        {
            trace::error("{} write sequence number overflow: {}", SessTag, write_sequence_);
            ec = fault::code::crypto_error;
            co_return 0;
        }

        const auto nonce = common::make_aead_nonce(
            std::span<const std::uint8_t>(keys_.server_app_iv.data(), keys_.server_app_iv.size()),
            write_sequence_);
        ++write_sequence_;

        const auto encrypted_len = static_cast<std::uint16_t>(inner.size() + tls::AEAD_TAG_LEN);
        const auto ad = common::make_record_ad(encrypted_len);

        write_ciphertext_buf_.resize(encrypted_len);
        auto &ciphertext = write_ciphertext_buf_;
        const auto nonce_span = std::span<const std::uint8_t>{nonce.data(), nonce.size()};
        const auto ad_span = std::span<const std::uint8_t>{ad.data(), ad.size()};
        const auto enc_ec = server_encryptor_.seal(ciphertext, inner, nonce_span, ad_span);
        if (!first_write_logged_)
        {
            first_write_logged_ = true;
            trace::debug("{} first encrypt: seq={}, plain_len={}", SessTag, write_sequence_ - 1, inner.size());
        }
        if (fault::failed(enc_ec))
        {
            trace::error("{} AEAD encrypt failed", SessTag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 合并写入：record_header + ciphertext
        std::array<std::byte, tls::RECORD_HEADER_LEN> record_header{};
        record_header[0] = static_cast<std::byte>(tls::CONTENT_TYPE_APPLICATION_DATA);
        record_header[1] = static_cast<std::byte>(0x03);
        record_header[2] = static_cast<std::byte>(0x03);
        record_header[3] = static_cast<std::byte>((encrypted_len >> 8) & 0xFF);
        record_header[4] = static_cast<std::byte>(encrypted_len & 0xFF);

        const std::size_t scatter_total = tls::RECORD_HEADER_LEN + ciphertext.size();
        scatter_buf_.resize(scatter_total);
        std::memcpy(scatter_buf_.data(), record_header.data(), tls::RECORD_HEADER_LEN);
        std::memcpy(scatter_buf_.data() + tls::RECORD_HEADER_LEN, ciphertext.data(), ciphertext.size());
        co_await transport::async_write(*transport_, scatter_buf_, ec);
        if (ec)
            co_return 0;

        co_return data.size();
    }
} // namespace psm::stealth::reality
