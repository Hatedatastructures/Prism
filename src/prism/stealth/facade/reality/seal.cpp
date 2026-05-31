#include <prism/stealth/facade/reality/seal.hpp>

#include <prism/protocol/tls/record.hpp>
#include <prism/stealth/common.hpp>
#include <prism/trace.hpp>
#include <prism/transport/transmission.hpp>

#include <algorithm>
#include <cstring>


namespace psm::stealth::reality
{

    namespace tls = psm::protocol::tls;

    namespace
    {
        constexpr std::string_view tag = "[Stealth.Session]";
    } // namespace

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
            trace::error("{} executor called with null transport", tag);
            throw std::runtime_error("seal::executor() called with null transport");
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
        std::span<const std::byte> chunk;
        if (buffer.size() > max_chunk)
            chunk = std::span<const std::byte>(buffer.data(), max_chunk);
        else
            chunk = buffer;
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
        auto [read_ec, rec] = co_await ::psm::tls::record::read(*transport_);
        if (fault::failed(read_ec))
        {
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        const auto content_type = rec.header().content_type;
        auto payload = rec.payload();
        const auto record_len = static_cast<std::size_t>(rec.header().length);

        if (content_type == tls::CT_ALERT)
        {
            trace::debug("{} received TLS alert record", tag);
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        if (content_type != tls::CT_APPLICATION_DATA)
        {
            trace::warn("{} unexpected content type: 0x{:02x}", tag, content_type);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        if (record_len < tls::AEAD_TAG_LEN)
        {
            trace::error("{} record too short for AEAD tag", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        if (read_seq_ >= UINT64_MAX - 1)
        {
            trace::error("{} read sequence number overflow: {}", tag, read_seq_);
            ec = fault::code::crypto_error;
            co_return 0;
        }

        const auto nonce = common::aead_nonce(
            std::span<const std::uint8_t>(keys_.client_appiv.data(), keys_.client_appiv.size()),
            read_seq_);
        ++read_seq_;

        // 类型转换：byte 载荷视图转 uint8_t 供 AEAD 解密
        const auto ciphertext = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size());
        const auto plaintext_len = payload.size() - tls::AEAD_TAG_LEN;

        dec_buf_.resize(plaintext_len);
        auto &decrypted = dec_buf_;

        // AEAD AD 从 record 序列化中取前 5 字节
        auto rec_bytes = rec.serialize();
        const auto ad_span = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(rec_bytes.data()), 5);
        const auto nonce_span = std::span<const std::uint8_t>{nonce.data(), nonce.size()};
        const auto dec_ec = cli_decryptor_.open(crypto::open_input{decrypted, ciphertext, nonce_span, ad_span});
        if (!first_read_log_)
        {
            first_read_log_ = true;
            trace::debug("{} first decrypt: seq={}, cipher_len={}",
                        tag, read_seq_ - 1, ciphertext.size());
        }
        if (fault::failed(dec_ec))
        {
            trace::error("{} AEAD decrypt failed", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // TLS 1.3 内部明文格式：去掉零填充和 content_type
        std::size_t data_end = decrypted.size();
        while (data_end > 0 && decrypted[data_end - 1] == 0x00)
        {
            --data_end;
        }
        if (data_end > 0)
        {
            --data_end;
        }

        plainbuf_.clear();
        plain_off_ = 0;
        plainbuf_.resize(data_end);
        if (data_end > 0)
        {
            std::memcpy(plainbuf_.data(), decrypted.data(), data_end);
        }

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
            trace::error("{} write sequence number overflow: {}", tag, write_seq_);
            ec = fault::code::crypto_error;
            co_return 0;
        }

        const auto nonce = common::aead_nonce(
            std::span<const std::uint8_t>(keys_.server_appiv.data(), keys_.server_appiv.size()),
            write_seq_);
        ++write_seq_;

        const auto encrypted_len = static_cast<std::uint16_t>(inner.size() + tls::AEAD_TAG_LEN);

        wr_cipher_buf_.resize(encrypted_len);
        auto &ciphertext = wr_cipher_buf_;

        // 类型转换：byte 视图转 uint8_t 供 AEAD
        const auto inner_span = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(inner.data()), inner.size());
        const auto nonce_span = std::span<const std::uint8_t>{nonce.data(), nonce.size()};

        // AEAD AD 使用 record_ad 生成
        const auto ad = common::record_ad(encrypted_len);
        const auto ad_span = std::span<const std::uint8_t>{ad.data(), ad.size()};
        const auto enc_ec = srv_encryptor_.seal(crypto::seal_input{ciphertext, inner_span, nonce_span, ad_span});
        if (!first_write_log_)
        {
            first_write_log_ = true;
            trace::debug("{} first encrypt: seq={}, plain_len={}", tag, write_seq_ - 1, inner.size());
        }
        if (fault::failed(enc_ec))
        {
            trace::error("{} AEAD encrypt failed", tag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 构造加密 TLS 记录并写入
        auto sealed = ::psm::tls::record::builder()
            .type(tls::CT_APPLICATION_DATA)
            .version(0x0303)
            .payload_u8(std::span<const std::uint8_t>(ciphertext.data(), ciphertext.size()))
            .build();

        auto write_ec = co_await sealed.write(*transport_);
        if (fault::failed(write_ec))
        {
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        co_return data.size();
    }
} // namespace psm::stealth::reality
