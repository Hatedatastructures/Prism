#include <prism/stealth/facade/shadowtls/transport.hpp>

#include <prism/net/transport/reliable.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/protocol/tls/record.hpp>
#include <prism/stealth/common.hpp>
#include <prism/trace/trace.hpp>

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstdint>
#include <cstring>

using namespace psm::trace;

namespace psm::stealth::shadowtls
{

    namespace
    {
        /// 计算 XOR 密钥：SHA256(password + serverRandom)
        [[nodiscard]] auto compute_write_key(std::string_view password, std::span<const std::byte> server_random)
            -> memory::vector<std::uint8_t>
        {
            SHA256_CTX sha_ctx;
            SHA256_Init(&sha_ctx);
            SHA256_Update(&sha_ctx, password.data(), password.size());
            SHA256_Update(&sha_ctx, reinterpret_cast<const std::uint8_t *>(server_random.data()),
                         server_random.size());
            memory::vector<std::uint8_t> key(32);
            SHA256_Final(key.data(), &sha_ctx);
            return key;
        }
    } // namespace

    shadowtls_transport::shadowtls_transport(transport::shared_transmission lower,
                                             shadowtls_handover handover)
        : lower_(std::move(lower))
        , write_key_(compute_write_key(handover.password, handover.server_random))
        , initial_buffer_(handover.initial_data.begin(), handover.initial_data.end())
        , hmac_write_ctx_(std::move(handover.hmac_write_ctx))
        , hmac_read_ctx_(std::move(handover.hmac_read_ctx))
    {
        std::memcpy(server_random_.data(), handover.server_random.data(), handover.server_random.size());

        const auto *hw_str = "no";
        if (hmac_write_ctx_)
            hw_str = "yes";
        const auto *hr_str = "no";
        if (hmac_read_ctx_)
            hr_str = "yes";
        trace::debug<flt::conn | flt::protocol>(prefix_, "shadowtls_transport created, initial_data_size={}, hmac_write_ctx={}, hmac_read_ctx={}",
                    handover.initial_data.size(), hw_str, hr_str);
    }

    shadowtls_transport::~shadowtls_transport() noexcept
    {
    }


    auto shadowtls_transport::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        trace::debug<flt::conn | flt::protocol>(prefix_, "async_read_some: buf={}, init_off={}, init_sz={}, pend_off={}, pend_sz={}",
                    buffer.size(), initial_offset_, initial_buffer_.size(), pending_offset_, pending_buffer_.size());

        if (initial_offset_ < initial_buffer_.size())
        {
            const auto available = initial_buffer_.size() - initial_offset_;
            const auto n = std::min(available, buffer.size());
            std::memcpy(buffer.data(), initial_buffer_.data() + initial_offset_, n);
            initial_offset_ += n;
            trace::debug<flt::conn | flt::protocol>(prefix_, "returned {} from initial, off={}", n, initial_offset_);
            co_return n;
        }

        if (pending_offset_ < pending_buffer_.size())
        {
            const auto available = pending_buffer_.size() - pending_offset_;
            const auto n = std::min(available, buffer.size());
            std::memcpy(buffer.data(), pending_buffer_.data() + pending_offset_, n);
            pending_offset_ += n;

            if (pending_offset_ == pending_buffer_.size())
            {
                pending_buffer_.clear();
                pending_offset_ = 0;
            }

            trace::debug<flt::conn | flt::protocol>(prefix_, "returned {} from pending, rem={}", n, pending_buffer_.size());
            co_return n;
        }

        trace::debug<flt::conn | flt::protocol>(prefix_, "buffers empty, reading TLS frame");
        auto frame_opt = co_await read_tls_frame(ec);
        if (ec || !frame_opt)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, "read_tls_frame failed: {}", ec.message());
            co_return 0;
        }

        auto &frame = *frame_opt;
        trace::debug<flt::conn | flt::protocol>(prefix_, "TLS frame payload: {} bytes", frame.size());

        const auto n = std::min(frame.size(), buffer.size());
        std::memcpy(buffer.data(), frame.data(), n);

        if (frame.size() > n)
        {
            pending_buffer_.assign(frame.begin() + n, frame.end());
            pending_offset_ = 0;
            trace::debug<flt::conn | flt::protocol>(prefix_, "stored {} pending", pending_buffer_.size());
        }

        trace::debug<flt::conn | flt::protocol>(prefix_, "returned {} to user", n);
        co_return n;
    }


    auto shadowtls_transport::read_tls_frame(std::error_code &ec)
        -> net::awaitable<std::optional<memory::vector<std::byte>>>
    {
        trace::debug<flt::conn | flt::protocol>(prefix_, "read_tls_frame: starting to read TLS header");

        auto [read_ec, rec] = co_await ::psm::tls::record::read(*lower_);
        if (fault::failed(read_ec))
        {
            ec = std::make_error_code(std::errc::connection_reset);
            trace::warn<flt::conn | flt::protocol>(prefix_, "read TLS record failed");
            co_return std::nullopt;
        }

        if (rec.header().content_type != content_appdata)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, "unexpected TLS record type: 0x{:02x}", rec.header().content_type);
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        auto payload = rec.payload();

        if (payload.size() < hmac_size)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, "payload too small for HMAC: {}", payload.size());
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        std::array<std::uint8_t, hmac_size> client_hmac{};
        std::memcpy(client_hmac.data(), payload.data(), hmac_size);

        auto actual_data = std::span<const std::byte>(
            payload.data() + hmac_size, payload.size() - hmac_size);

        if (!hmac_read_ctx_)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, "hmac_read_ctx is null, cannot verify HMAC");
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        HMAC_Update(hmac_read_ctx_.get(),
                   reinterpret_cast<const std::uint8_t *>(actual_data.data()),
                   actual_data.size());

        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        {
            HMAC_CTX *hmac_copy = HMAC_CTX_new();
            HMAC_CTX_copy(hmac_copy, hmac_read_ctx_.get());
            HMAC_Final(hmac_copy, md.data(), &md_len);
            HMAC_CTX_free(hmac_copy);
        }

        std::array<std::uint8_t, hmac_size> expected_hmac{};
        std::memcpy(expected_hmac.data(), md.data(), hmac_size);

        if (CRYPTO_memcmp(client_hmac.data(), expected_hmac.data(), hmac_size) != 0)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, "HMAC mismatch in transport read_tls_frame");
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        HMAC_Update(hmac_read_ctx_.get(), client_hmac.data(), hmac_size);

        trace::debug<flt::conn | flt::protocol>(prefix_, "TLS frame verified (cumulative HMAC), payload_size={}, added HMAC to cumulative state",
                    actual_data.size());

        memory::vector<std::byte> result(actual_data.begin(), actual_data.end());
        co_return result;
    }


    auto shadowtls_transport::async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        trace::debug<flt::conn | flt::protocol>(prefix_, "async_write_some: buffer_size={}, calling write_tls_frame", buffer.size());
        return write_tls_frame(buffer, ec);
    }


    auto shadowtls_transport::async_write(std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        trace::debug<flt::conn | flt::protocol>(prefix_, "async_write: data_size={}, calling write_tls_frame directly", data.size());
        return write_tls_frame(data, ec);
    }


    auto shadowtls_transport::write_tls_frame(std::span<const std::byte> payload, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();
        trace::debug<flt::conn | flt::protocol>(prefix_, "write_tls_frame: payload_size={}", payload.size());

        HMAC_Update(hmac_write_ctx_.get(),
                   reinterpret_cast<const std::uint8_t *>(payload.data()),
                   payload.size());

        HMAC_CTX *hmac_copy = HMAC_CTX_new();
        HMAC_CTX_copy(hmac_copy, hmac_write_ctx_.get());
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        HMAC_Final(hmac_copy, md.data(), &md_len);
        HMAC_CTX_free(hmac_copy);

        std::array<std::uint8_t, hmac_size> hmac_tag{};
        std::memcpy(hmac_tag.data(), md.data(), hmac_size);

        HMAC_Update(hmac_write_ctx_.get(), hmac_tag.data(), hmac_size);

        memory::vector<std::byte> tls_payload(hmac_size + payload.size());
        std::memcpy(tls_payload.data(), hmac_tag.data(), hmac_size);
        std::memcpy(tls_payload.data() + hmac_size, payload.data(), payload.size());

        auto frame_rec = ::psm::tls::record::builder()
                             .type(content_appdata)
                             .version(0x0303)
                             .payload(tls_payload)
                             .build();
        auto frame_bytes = frame_rec.serialize();

        std::error_code write_ec;
        co_await transport::async_write(
            *lower_,
            std::span<const std::byte>(frame_bytes.data(), frame_bytes.size()),
            write_ec);

        if (write_ec)
        {
            ec = write_ec;
            trace::warn<flt::conn | flt::protocol>(prefix_, "write TLS frame failed: {}", write_ec.message());
            co_return 0;
        }

        trace::debug<flt::conn | flt::protocol>(prefix_, "wrote {} bytes (TLS frame size={})", payload.size(), frame_bytes.size());
        co_return payload.size();
    }


    void shadowtls_transport::shutdown_write()
    {
        if (auto *rel = lowest_layer<transport::reliable>())
            rel->shutdown_write();
    }


    void shadowtls_transport::close()
    {
        lower_->close();
    }


    void shadowtls_transport::cancel()
    {
        lower_->cancel();
    }
} // namespace psm::stealth::shadowtls
