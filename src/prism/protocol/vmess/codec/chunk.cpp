/**
 * @file chunk.cpp
 * @brief VMess 数据分块流编解码实现
 */

#include <prism/protocol/vmess/codec/chunk.hpp>

#include <prism/protocol/common/read.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <cstring>

namespace psm::protocol::vmess::codec
{

    namespace
    {
        /// 选项位掩码查询
        [[nodiscard]] inline auto has_option(const std::uint8_t option, const std::uint8_t bit) noexcept
            -> bool
        {
            return (option & bit) != 0;
        }

        /// 创建 AEAD 上下文
        [[nodiscard]] auto make_aead(const std::uint8_t security, const std::span<const std::uint8_t, 16> key)
            -> std::unique_ptr<EVP_AEAD_CTX, void (*)(EVP_AEAD_CTX *)>
        {
            const EVP_AEAD *aead = nullptr;
            switch (security)
            {
            case static_cast<std::uint8_t>(security::aes_128_gcm):
            case static_cast<std::uint8_t>(security::auto_):
                aead = EVP_aead_aes_128_gcm();
                break;
            case static_cast<std::uint8_t>(security::chacha20_poly1305):
                aead = EVP_aead_chacha20_poly1305();
                break;
            default:
                return {nullptr, &EVP_AEAD_CTX_cleanup};
            }
            auto *ctx = new EVP_AEAD_CTX;
            EVP_AEAD_CTX_zero(ctx);
            if (!EVP_AEAD_CTX_init(ctx, aead, key.data(), key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr))
            {
                EVP_AEAD_CTX_cleanup(ctx);
                delete ctx;
                return {nullptr, &EVP_AEAD_CTX_cleanup};
            }
            return {ctx, [](EVP_AEAD_CTX *c)
                    {
                        if (c)
                        {
                            EVP_AEAD_CTX_cleanup(c);
                            delete c;
                        }
                    }};
        }

        /// 组装数据层 nonce（2B 计数 + 10B 源）
        [[nodiscard]] inline auto make_nonce(const std::uint16_t count, const std::span<const std::uint8_t, 16> src)
            -> std::array<std::uint8_t, 12>
        {
            std::array<std::uint8_t, 12> nonce{};
            nonce[0] = static_cast<std::uint8_t>(count >> 8);
            nonce[1] = static_cast<std::uint8_t>(count & 0xFF);
            std::memcpy(nonce.data() + 2, src.data() + 2, 10);
            return nonce;
        }

        // === Keccak-f[1600] ===

        constexpr std::array<std::uint64_t, 24> round_constants{
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
            0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
            0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
            0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
            0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
            0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
            0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

        [[nodiscard]] constexpr auto rotl(const std::uint64_t v, const int n) noexcept -> std::uint64_t
        {
            return n == 0 ? v : ((v << n) | (v >> (64 - n)));
        }

        void keccak_f(std::array<std::uint64_t, 25> &st) noexcept
        {
            for (const auto rc : round_constants)
            {
                // θ
                std::array<std::uint64_t, 5> c{};
                for (std::size_t i = 0; i < 5; ++i)
                {
                    c[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
                }
                for (std::size_t i = 0; i < 5; ++i)
                {
                    const auto d = c[(i + 4) % 5] ^ rotl(c[(i + 1) % 5], 1);
                    for (std::size_t j = 0; j < 25; j += 5)
                        st[j + i] ^= d;
                }
                // ρ + π：Go x/crypto/sha3 链式展开（piln/rotc 表）
                static constexpr std::array<int, 24> piln{
                    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
                static constexpr std::array<int, 24> rotc{
                    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
                std::uint64_t t = st[1];
                for (int x = 0; x < 24; ++x)
                {
                    const int j = piln[x];
                    const auto tmp = st[j];
                    st[j] = rotl(t, rotc[x]);
                    t = tmp;
                }
                // χ：bc 缓存一行后就地写（与 Go 一致）
                std::array<std::uint64_t, 5> bc{};
                for (std::size_t y = 0; y < 25; y += 5)
                {
                    for (std::size_t x = 0; x < 5; ++x)
                        bc[x] = st[y + x];
                    for (std::size_t x = 0; x < 5; ++x)
                        st[y + x] = bc[x] ^ ((~bc[(x + 1) % 5]) & bc[(x + 2) % 5]);
                }
                // ι
                st[0] ^= rc;
            }
        }
    } // namespace

    shake_stream::shake_stream(const std::span<const std::uint8_t> seed)
    {
        // absorb：异或输入到 state 前 168 字节
        std::size_t offset = 0;
        auto *block = reinterpret_cast<std::uint8_t *>(state_.data());
        while (seed.size() - offset >= 168)
        {
            for (std::size_t i = 0; i < 168; ++i)
                block[i] ^= seed[offset + i];
            keccak_f(state_);
            offset += 168;
        }
        // 最后一块：域分隔 0x1F 异或进当前吸收位置（与 Go sha3.padAndPermute 一致），
        // 终止位 0x80 异或进 rate-1（167）位置
        const std::size_t rest = seed.size() - offset;
        if (rest > 0)
        {
            for (std::size_t i = 0; i < rest; ++i)
                block[i] ^= seed[offset + i];
        }
        block[rest] ^= 0x1F;
        block[167] ^= 0x80;
        // squeeze 首次输出
        keccak_f(state_);
    }

    auto shake_stream::next() -> std::span<const std::uint8_t>
    {
        if (cursor_ == 168)
        {
            std::memcpy(buffer_.data(), state_.data(), 168);
            keccak_f(state_);
            cursor_ = 0;
        }
        const std::size_t begin = cursor_;
        cursor_ = 168;
        return std::span<const std::uint8_t>(buffer_.data() + begin, 168 - begin);
    }

    read_stream::read_stream(const stream_params params)
        : params_(params)
        , aead_(make_aead(params.security, std::span<const std::uint8_t, 16>(params.key.data(), 16)))
    {
        const bool masking = has_option(params.option, static_cast<std::uint8_t>(option::chunk_masking));
        const bool padding = has_option(params.option, static_cast<std::uint8_t>(option::global_padding));
        if (masking)
            mask_stream_ = std::make_unique<shake_stream>(params.nonce);
        if (padding)
            padding_stream_ = std::make_unique<shake_stream>(params.nonce);
    }

    auto read_stream::read_chunk(std::span<std::byte> out, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        // 读长度头
        std::array<std::byte, 2> len_buf{};
        const auto [read_ec, got] = co_await protocol::common::read_min(
            *params_.transport, len_buf, len_buf.size());
        if (fault::failed(read_ec))
        {
            ec = std::make_error_code(std::errc::bad_message);
            co_return 0;
        }
        (void)got;
        std::uint16_t len = static_cast<std::uint16_t>(
            (static_cast<std::uint8_t>(len_buf[0]) << 8) | static_cast<std::uint8_t>(len_buf[1]));

        // 消费 padding 长度（GlobalPadding 先于 ChunkMasking）
        std::size_t padding_len = 0;
        if (padding_stream_)
        {
            const auto stream = padding_stream_->next();
            if (stream.size() < 2)
            {
                ec = std::make_error_code(std::errc::bad_message);
                co_return 0;
            }
            const std::uint16_t code = static_cast<std::uint16_t>((stream[0] << 8) | stream[1]);
            padding_len = code % max_padding_len;
        }

        // 掩码异或
        if (mask_stream_)
        {
            const auto stream = mask_stream_->next();
            if (stream.size() < 2)
            {
                ec = std::make_error_code(std::errc::bad_message);
                co_return 0;
            }
            const std::uint16_t mask = static_cast<std::uint16_t>((stream[0] << 8) | stream[1]);
            len ^= mask;
        }

        if (len == 0)
        {
            ec = {};
            co_return 0; // EOF
        }

        std::size_t data_len = len;
        if (data_len < padding_len)
        {
            ec = std::make_error_code(std::errc::bad_message);
            co_return 0;
        }
        data_len -= padding_len;

        // 读密文
        std::array<std::byte, max_chunk_len + 16> cipher_buf{};
        if (data_len > cipher_buf.size() || data_len > out.size() + 16)
        {
            ec = std::make_error_code(std::errc::bad_message);
            co_return 0;
        }
        const auto [read_ec2, got2] = co_await protocol::common::read_min(
            *params_.transport, std::span<std::byte>(cipher_buf.data(), data_len), data_len);
        if (fault::failed(read_ec2))
        {
            ec = std::make_error_code(std::errc::bad_message);
            co_return 0;
        }
        (void)got2;

        // 丢弃 padding
        std::size_t remaining = padding_len;
        while (remaining > 0)
        {
            std::array<std::byte, 64> discard{};
            const auto n = std::min(remaining, discard.size());
            const auto [d_ec, got3] = co_await protocol::common::read_min(
                *params_.transport, std::span<std::byte>(discard.data(), n), n);
            if (fault::failed(d_ec))
            {
                ec = std::make_error_code(std::errc::bad_message);
                co_return 0;
            }
            (void)got3;
            remaining -= n;
        }

        // 解密
        if (!aead_)
        {
            // security=none/zero：明文直读
            std::memcpy(out.data(), cipher_buf.data(), data_len);
            ec = {};
            co_return data_len;
        }
        const auto nonce = make_nonce(nonce_count_++, params_.nonce);
        std::size_t out_len = 0;
        if (!EVP_AEAD_CTX_open(aead_.get(), reinterpret_cast<std::uint8_t *>(out.data()), &out_len,
                               out.size(), nonce.data(), nonce.size(),
                               reinterpret_cast<const std::uint8_t *>(cipher_buf.data()), data_len,
                               nullptr, 0))
        {
            ec = std::make_error_code(std::errc::bad_message);
            co_return 0;
        }
        ec = {};
        co_return out_len;
    }

    write_stream::write_stream(const stream_params params)
        : params_(params)
        , aead_(make_aead(params.security, std::span<const std::uint8_t, 16>(params.key.data(), 16)))
    {
        const bool masking = has_option(params.option, static_cast<std::uint8_t>(option::chunk_masking));
        const bool padding = has_option(params.option, static_cast<std::uint8_t>(option::global_padding));
        if (masking)
            mask_stream_ = std::make_unique<shake_stream>(params.nonce);
        if (padding)
            padding_stream_ = std::make_unique<shake_stream>(params.nonce);
    }

    auto write_stream::write_chunk(std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (data.size() > max_chunk_len)
        {
            ec = std::make_error_code(std::errc::message_size);
            co_return 0;
        }

        // 密封
        std::array<std::byte, max_chunk_len + 16> cipher_buf{};
        std::size_t cipher_len = data.size();
        if (aead_)
        {
            const auto nonce = make_nonce(nonce_count_++, params_.nonce);
            if (!EVP_AEAD_CTX_seal(aead_.get(), reinterpret_cast<std::uint8_t *>(cipher_buf.data()),
                                   &cipher_len, cipher_buf.size(), nonce.data(), nonce.size(),
                                   reinterpret_cast<const std::uint8_t *>(data.data()), data.size(),
                                   nullptr, 0))
            {
                ec = std::make_error_code(std::errc::bad_message);
                co_return 0;
            }
        }
        else
        {
            std::memcpy(cipher_buf.data(), data.data(), data.size());
        }

        // 组装长度头
        std::size_t padding_len = 0;
        if (padding_stream_)
        {
            const auto stream = padding_stream_->next();
            if (stream.size() < 2)
            {
                ec = std::make_error_code(std::errc::bad_message);
                co_return 0;
            }
            const std::uint16_t code = static_cast<std::uint16_t>((stream[0] << 8) | stream[1]);
            padding_len = code % max_padding_len;
        }

        std::uint16_t masked_len = static_cast<std::uint16_t>(cipher_len + padding_len);
        if (mask_stream_)
        {
            const auto stream = mask_stream_->next();
            if (stream.size() < 2)
            {
                ec = std::make_error_code(std::errc::bad_message);
                co_return 0;
            }
            const std::uint16_t mask = static_cast<std::uint16_t>((stream[0] << 8) | stream[1]);
            masked_len ^= mask;
        }

        std::array<std::byte, 2> len_buf{
            static_cast<std::byte>(masked_len >> 8), static_cast<std::byte>(masked_len & 0xFF)};

        // 写出：len + 密文 + padding
        std::error_code w_ec;
        co_await params_.transport->async_write_some(len_buf, w_ec);
        if (w_ec)
        {
            ec = w_ec;
            co_return 0;
        }
        co_await params_.transport->async_write_some(
            std::span<const std::byte>(cipher_buf.data(), cipher_len), w_ec);
        if (w_ec)
        {
            ec = w_ec;
            co_return 0;
        }
        if (padding_len > 0)
        {
            std::array<std::byte, 64> pad{};
            if (RAND_bytes(reinterpret_cast<std::uint8_t *>(pad.data()), pad.size()) != 1)
            {
                ec = std::make_error_code(std::errc::bad_message);
                co_return 0;
            }
            co_await params_.transport->async_write_some(
                std::span<const std::byte>(pad.data(), padding_len), w_ec);
            if (w_ec)
            {
                ec = w_ec;
                co_return 0;
            }
        }
        ec = {};
        co_return data.size();
    }

    auto write_stream::finish(std::error_code &ec) -> net::awaitable<std::size_t>
    {
        // 终止块：len=0（掩码时异或下一掩码）
        std::uint16_t masked_len = 0;
        if (mask_stream_)
        {
            const auto stream = mask_stream_->next();
            if (stream.size() < 2)
            {
                ec = std::make_error_code(std::errc::bad_message);
                co_return 0;
            }
            const std::uint16_t mask = static_cast<std::uint16_t>((stream[0] << 8) | stream[1]);
            masked_len ^= mask;
        }
        std::array<std::byte, 2> len_buf{
            static_cast<std::byte>(masked_len >> 8), static_cast<std::byte>(masked_len & 0xFF)};
        std::error_code w_ec;
        const auto n = co_await params_.transport->async_write_some(len_buf, w_ec);
        ec = w_ec;
        co_return n;
    }

} // namespace psm::protocol::vmess::codec

