#include <prism/stealth/reality/seal.hpp>
#include <prism/stealth/common.hpp>
#include <prism/trace.hpp>
#include <prism/transport/transmission.hpp>
#include <cstring>
#include <algorithm>

namespace psm::stealth::reality
{
    namespace tls = psm::protocol::tls;

    constexpr std::string_view SessTag = "[Stealth.Session]";

    seal::seal(transport::shared_transmission transport, key_material keys)
        : transport_(std::move(transport)),
          keys_(keys),
          srv_encryptor_(crypto::aead_cipher::aes_128_gcm, keys_.server_appkey),
          cli_decryptor_(crypto::aead_cipher::aes_128_gcm, keys_.client_appkey)
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
        if (plain_off_ < plainbuf_.size())
        {
            const auto remaining = plainbuf_.size() - plain_off_;
            const auto to_copy = std::min(remaining, buffer.size());
            std::memcpy(buffer.data(), plainbuf_.data() + plain_off_, to_copy);
            plain_off_ += to_copy;

            if (plain_off_ >= plainbuf_.size())
            {
                plainbuf_.clear();
                plain_off_ = 0;
            }
            co_return to_copy;
        }

        // 缓冲区空了，读取新的加密 TLS 记录
        const auto n = co_await recv_record(ec);
        if (ec || n == 0)
            co_return 0;

        // 解密后数据已填入缓冲区
        if (plain_off_ < plainbuf_.size())
        {
            const auto remaining = plainbuf_.size() - plain_off_;
            const auto to_copy = std::min(remaining, buffer.size());
            std::memcpy(buffer.data(), plainbuf_.data() + plain_off_, to_copy);
            plain_off_ += to_copy;

            if (plain_off_ >= plainbuf_.size())
            {
                plainbuf_.clear();
                plain_off_ = 0;
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
        constexpr std::size_t max_chunk = 16383;
        const auto chunk = buffer.size() > max_chunk
            ? std::span<const std::byte>(buffer.data(), max_chunk)
            : buffer;
        const auto written = co_await send_record(chunk, ec);
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

    auto seal::recv_record(std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        // 1. 读取 TLS 记录头
        std::array<std::byte, tls::RECORD_HDR_LEN> header{};
        std::size_t hdr_read = 0;
        while (hdr_read < tls::RECORD_HDR_LEN)
        {
            const auto n = co_await transport_->async_read_some(
                std::span<std::byte>(header.data() + hdr_read, tls::RECORD_HDR_LEN - hdr_read), ec);
            if (ec || n == 0)
                co_return 0;
            hdr_read += n;
        }

        // safe: casting byte array to uint8_t to parse TLS record header fields
        const auto *raw = reinterpret_cast<const std::uint8_t *>(header.data());
        const auto content_type = raw[0];
        const auto record_len = (static_cast<std::size_t>(raw[3]) << 8) | static_cast<std::size_t>(raw[4]);

        // 2. 读取记录体
        recbody_buf_.resize(record_len);
        auto &record_body = recbody_buf_;
        std::size_t body_n = 0;
        while (body_n < record_len)
        {
            auto buf_span = std::span<std::byte>(record_body.data() + body_n, record_len - body_n);
            const auto n = co_await transport_->async_read_some(buf_span, ec);
            if (ec || n == 0)
                co_return 0;
            body_n += n;
        }

        // 3. 处理内容类型
        if (content_type == tls::CT_ALERT)
        {
            trace::debug("{} received TLS alert record", SessTag);
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        if (content_type != tls::CT_APPLICATION_DATA)
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
        if (read_seq_ >= UINT64_MAX - 1)
        {
            trace::error("{} read sequence number overflow: {}", SessTag, read_seq_);
            ec = fault::code::crypto_error;
            co_return 0;
        }

        // 5. AEAD 解密
        const auto nonce = common::make_aead_nonce(
            std::span<const std::uint8_t>(keys_.client_appiv.data(), keys_.client_appiv.size()),
            read_seq_);
        ++read_seq_;

        const auto ad = common::make_record_ad((static_cast<std::uint16_t>(raw[3]) << 8) | raw[4]);

        // safe: casting byte vector to uint8_t span for AEAD ciphertext input
        const auto ciphertext = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(record_body.data()), record_len);
        const auto plaintext_len = record_len - tls::AEAD_TAG_LEN;

        dec_buf_.resize(plaintext_len);
        auto &decrypted = dec_buf_;
        const auto nonce_span = std::span<const std::uint8_t>{nonce.data(), nonce.size()};
        const auto ad_span = std::span<const std::uint8_t>{ad.data(), ad.size()};
        const auto dec_ec = cli_decryptor_.open(decrypted, ciphertext, nonce_span, ad_span);
        if (!first_read_log_)
        {
            first_read_log_ = true;
            trace::debug("{} first decrypt: seq={}, cipher_len={}",
                        SessTag, read_seq_ - 1, ciphertext.size());
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
        plainbuf_.clear();
        plain_off_ = 0;
        plainbuf_.resize(data_end);
        if (data_end > 0)
            std::memcpy(plainbuf_.data(), decrypted.data(), data_end);

        co_return plainbuf_.size();
    }

    auto seal::send_record(const std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (data.empty())
        {
            ec.clear();
            co_return 0;
        }

        // TLS 1.3 内部明文
        wr_plain_buf_.resize(data.size() + 1);
        std::memcpy(wr_plain_buf_.data(), data.data(), data.size());
        wr_plain_buf_[data.size()] = tls::CT_APPLICATION_DATA;
        auto &inner = wr_plain_buf_;

        // 序列号溢出检测
        if (write_seq_ >= UINT64_MAX - 1)
        {
            trace::error("{} write sequence number overflow: {}", SessTag, write_seq_);
            ec = fault::code::crypto_error;
            co_return 0;
        }

        const auto nonce = common::make_aead_nonce(
            std::span<const std::uint8_t>(keys_.server_appiv.data(), keys_.server_appiv.size()),
            write_seq_);
        ++write_seq_;

        const auto encrypted_len = static_cast<std::uint16_t>(inner.size() + tls::AEAD_TAG_LEN);
        const auto ad = common::make_record_ad(encrypted_len);

        wr_cipher_buf_.resize(encrypted_len);
        auto &ciphertext = wr_cipher_buf_;
        const auto nonce_span = std::span<const std::uint8_t>{nonce.data(), nonce.size()};
        const auto ad_span = std::span<const std::uint8_t>{ad.data(), ad.size()};
        const auto enc_ec = srv_encryptor_.seal(ciphertext, inner, nonce_span, ad_span);
        if (!first_write_log_)
        {
            first_write_log_ = true;
            trace::debug("{} first encrypt: seq={}, plain_len={}", SessTag, write_seq_ - 1, inner.size());
        }
        if (fault::failed(enc_ec))
        {
            trace::error("{} AEAD encrypt failed", SessTag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 合并写入：rec_hdr + ciphertext
        std::array<std::byte, tls::RECORD_HDR_LEN> rec_hdr{};
        rec_hdr[0] = static_cast<std::byte>(tls::CT_APPLICATION_DATA);
        rec_hdr[1] = static_cast<std::byte>(0x03);
        rec_hdr[2] = static_cast<std::byte>(0x03);
        rec_hdr[3] = static_cast<std::byte>((encrypted_len >> 8) & 0xFF);
        rec_hdr[4] = static_cast<std::byte>(encrypted_len & 0xFF);

        const std::size_t scatter_total = tls::RECORD_HDR_LEN + ciphertext.size();
        scatter_buf_.resize(scatter_total);
        std::memcpy(scatter_buf_.data(), rec_hdr.data(), tls::RECORD_HDR_LEN);
        std::memcpy(scatter_buf_.data() + tls::RECORD_HDR_LEN, ciphertext.data(), ciphertext.size());
        co_await transport::async_write(*transport_, scatter_buf_, ec);
        if (ec)
            co_return 0;

        co_return data.size();
    }
} // namespace psm::stealth::reality
