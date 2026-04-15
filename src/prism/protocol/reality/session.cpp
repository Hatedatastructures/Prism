#include <prism/protocol/reality/session.hpp>
#include <prism/trace.hpp>
#include <cstring>
#include <algorithm>

namespace psm::protocol::reality
{
    constexpr std::string_view SessTag = "[Reality.Session]";

    // 构造加密传输层会话。持有底层传输层和所有 TLS 1.3 应用数据密钥。
    // 服务端加密（seal）和客户端解密（open）各用一个独立的 AEAD 上下文，
    // 因为 TLS 1.3 的服务器和客户端使用不同的密钥（不像 TLS 1.2 的对称密钥）。
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

    // 读取解密后的明文数据。实现了内部缓冲机制：
    // - 一个 TLS 记录可能包含很多数据，调用方可能一次只要一小块
    // - 先把解密后的数据存入 plaintext_buffer_，然后按需切片返回
    // - 缓冲区消耗完了，才去读取下一个加密记录
    auto session::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
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

            // 全部消费完，清空缓冲区释放内存
            if (plaintext_offset_ >= plaintext_buffer_.size())
            {
                plaintext_buffer_.clear();
                plaintext_offset_ = 0;
            }
            co_return to_copy;
        }

        // 缓冲区空了，从底层读取一个新的加密 TLS 记录并解密
        const auto n = co_await read_encrypted_record(ec);
        if (ec || n == 0)
        {
            co_return 0;
        }

        // 解密后数据已填入缓冲区，再次尝试返回
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

    // 计算 TLS 1.3 AEAD nonce：nonce = iv XOR sequence_number（大端序）。
    // 每条记录的 sequence_number 递增，保证每条记录使用不同的 nonce。
    // 这是 RFC 8446 Section 5.3 规定的 nonce 构造方式。
    auto session::make_nonce(const std::span<const std::uint8_t> iv, const std::uint64_t sequence) const
        -> std::array<std::uint8_t, tls::AEAD_NONCE_LEN>
    {
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> nonce{};
        std::memcpy(nonce.data(), iv.data(), tls::AEAD_NONCE_LEN);

        // 从 nonce 末尾开始 XOR sequence 的大端字节
        for (int i = 0; i < 8; ++i)
        {
            nonce[tls::AEAD_NONCE_LEN - 1 - i] ^= static_cast<std::uint8_t>((sequence >> (8 * i)) & 0xFF);
        }
        return nonce;
    }

    // 读取并解密一个完整的 TLS 1.3 应用数据记录。
    //
    // 流程：
    // 1. 读取 5 字节 TLS 记录头 → 获取 content_type 和 record_len
    // 2. 读取 record_len 字节的密文体
    // 3. 处理非应用数据记录（Alert = 连接关闭，其他 = 协议错误）
    // 4. 用客户端应用密钥解密密文 → 得到 TLS 1.3 内部明文
    // 5. 去掉末尾的 content_type 字节和零填充
    // 6. 将纯数据存入 plaintext_buffer_ 供 async_read_some 消费
    auto session::read_encrypted_record(std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        // 1. 读取 TLS 记录头（5 字节：type + version + length）
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

        // 解析记录头
        const auto *raw = reinterpret_cast<const std::uint8_t *>(header.data());
        const auto content_type = raw[0];
        const auto record_len = (static_cast<std::size_t>(raw[3]) << 8) | static_cast<std::size_t>(raw[4]);

        // 2. 读取记录体（密文）
        record_body_buf_.resize(record_len);
        auto &record_body = record_body_buf_;
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

        // 3. 按内容类型处理
        if (content_type == tls::CONTENT_TYPE_ALERT)
        {
            // TLS Alert：对端发来的告警，通常是 close_notify（正常关闭）
            trace::debug("{} received TLS alert record", SessTag);
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        if (content_type != tls::CONTENT_TYPE_APPLICATION_DATA)
        {
            // 握手完成后只应该收到应用数据记录（0x17）
            trace::warn("{} unexpected content type: 0x{:02x}", SessTag, content_type);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 4. 密文太短，放不下 AEAD 认证标签（16 字节）
        if (record_len < tls::AEAD_TAG_LEN)
        {
            trace::error("{} record too short for AEAD tag", SessTag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 5. 构造 nonce = client_iv XOR read_sequence_（每次递增）
        const auto nonce = make_nonce(keys_.client_app_iv, read_sequence_);
        ++read_sequence_;

        // 6. 构造 additional_data = 记录头（TLS 1.3 用记录头作为 AEAD 的 AAD）
        std::array<std::uint8_t, tls::RECORD_HEADER_LEN> ad{};
        ad[0] = tls::CONTENT_TYPE_APPLICATION_DATA;
        ad[1] = 0x03;
        ad[2] = 0x03;
        ad[3] = raw[3];
        ad[4] = raw[4];

        // 7. AEAD 解密：密文 → 明文（去掉 16 字节认证标签）
        const auto ciphertext = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(record_body.data()), record_len);
        const auto plaintext_len = record_len - tls::AEAD_TAG_LEN;

        decrypted_buf_.resize(plaintext_len);
        auto &decrypted = decrypted_buf_;
        const auto nonce_span = std::span<const std::uint8_t>{nonce.data(), nonce.size()};
        const auto ad_span = std::span<const std::uint8_t>{ad.data(), ad.size()};
        const auto dec_ec = client_decryptor_.open(decrypted, ciphertext, nonce_span, ad_span);
        if (fault::failed(dec_ec))
        {
            // 解密失败 = 密文被篡改或密钥不匹配
            trace::error("{} AEAD decrypt failed", SessTag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 8. TLS 1.3 内部明文格式: [实际数据][content_type(1字节)][零填充...]
        // 从末尾向前扫描，跳过零填充，找到 content_type 字节，
        // content_type 之前的才是真正的应用数据。
        std::size_t data_end = decrypted.size();
        while (data_end > 0 && decrypted[data_end - 1] == 0x00)
        {
            --data_end;
        }
        if (data_end > 0)
        {
            --data_end; // 跳过 content_type 字节本身
        }

        // 9. 将纯应用数据存入缓冲区，等待 async_read_some 消费
        plaintext_buffer_.clear();
        plaintext_offset_ = 0;
        plaintext_buffer_.resize(data_end);
        if (data_end > 0)
        {
            std::memcpy(plaintext_buffer_.data(), decrypted.data(), data_end);
        }

        co_return plaintext_buffer_.size();
    }

    // 加密并写入一个 TLS 1.3 应用数据记录。
    //
    // 流程：
    // 1. 构造 TLS 1.3 内部明文: 数据 + content_type(0x17)
    // 2. 计算 nonce = server_iv XOR write_sequence_
    // 3. 构造 additional_data = 记录头（类型=0x17, 版本=0x0303, 长度）
    // 4. AEAD 加密 → 密文（含 16 字节认证标签）
    // 5. 组装完整 TLS 记录（5 字节头 + 密文）并写入底层传输层
    auto session::write_encrypted_record(const std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (data.empty())
        {
            ec.clear();
            co_return 0;
        }

        // 1. TLS 1.3 内部明文: 数据 + content_type(0x17) 表示应用数据
        write_plain_buf_.resize(data.size() + 1);
        if (!data.empty())
        {
            std::memcpy(write_plain_buf_.data(), data.data(), data.size());
        }
        write_plain_buf_[data.size()] = tls::CONTENT_TYPE_APPLICATION_DATA;
        auto &inner = write_plain_buf_;

        // 2. nonce = server_iv XOR write_sequence_（每次递增）
        const auto nonce = make_nonce(keys_.server_app_iv, write_sequence_);
        ++write_sequence_;

        // 3. additional_data = 记录头（长度需要预计算：明文 + 16 字节认证标签）
        const auto encrypted_len = inner.size() + tls::AEAD_TAG_LEN;
        std::array<std::uint8_t, tls::RECORD_HEADER_LEN> ad{};
        ad[0] = tls::CONTENT_TYPE_APPLICATION_DATA;
        ad[1] = 0x03;
        ad[2] = 0x03;
        ad[3] = static_cast<std::uint8_t>((encrypted_len >> 8) & 0xFF);
        ad[4] = static_cast<std::uint8_t>(encrypted_len & 0xFF);

        // 4. AEAD 加密
        write_ciphertext_buf_.resize(encrypted_len);
        auto &ciphertext = write_ciphertext_buf_;
        const auto nonce_span = std::span<const std::uint8_t>{nonce.data(), nonce.size()};
        const auto ad_span = std::span<const std::uint8_t>{ad.data(), ad.size()};
        const auto enc_ec = server_encryptor_.seal(ciphertext, inner, nonce_span, ad_span);
        if (fault::failed(enc_ec))
        {
            trace::error("{} AEAD encrypt failed", SessTag);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return 0;
        }

        // 5. scatter-gather 写入：栈上记录头 + 成员密文缓冲区
        std::array<std::byte, tls::RECORD_HEADER_LEN> record_header{};
        record_header[0] = static_cast<std::byte>(tls::CONTENT_TYPE_APPLICATION_DATA);
        record_header[1] = static_cast<std::byte>(0x03);
        record_header[2] = static_cast<std::byte>(0x03);
        record_header[3] = static_cast<std::byte>((encrypted_len >> 8) & 0xFF);
        record_header[4] = static_cast<std::byte>(encrypted_len & 0xFF);

        const std::span<const std::byte> scatter_parts[] = {
            record_header,
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(ciphertext.data()),
                ciphertext.size())};
        co_await transport_->async_write_scatter(scatter_parts, 2, ec);
        if (ec)
        {
            co_return 0;
        }

        co_return data.size();
    }
} // namespace psm::protocol::reality
