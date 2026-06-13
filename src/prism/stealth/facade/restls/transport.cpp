#include <prism/stealth/facade/restls/transport.hpp>

#include <prism/proto/protocol/tls/record.hpp>
#include <prism/stealth/common.hpp>
#include <prism/trace/trace.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <openssl/crypto.h>

using namespace psm::trace;

namespace psm::stealth::restls
{

    namespace
    {
        constexpr std::uint8_t content_type_appdata = 0x17;

        struct tls_record
        {
            std::array<std::uint8_t, tls_hdrsize> header{};
            memory::vector<std::byte> payload;
        };

        struct decoded_payload
        {
            std::uint16_t data_len;
            std::uint16_t cmd;
        };

        struct decode_options
        {
            std::span<const std::uint8_t, 32> secret;
            std::span<const std::uint8_t, 32> server_random;
            std::uint64_t counter;
            std::array<std::uint8_t, tls_hdrsize> tls_header;
        };

        auto read_tls_record(net::ip::tcp::socket &socket, std::error_code &ec)
            -> net::awaitable<std::optional<tls_record>>
        {
            auto [read_ec, rec] = co_await ::psm::tls::record::read(socket);
            if (fault::failed(read_ec))
            {
                ec = std::make_error_code(std::errc::connection_reset);
                co_return std::nullopt;
            }

            if (rec.header().content_type != content_type_appdata)
            {
                ec = std::make_error_code(std::errc::protocol_error);
                co_return std::nullopt;
            }

            auto payload = rec.payload();
            memory::vector<std::byte> payload_copy(payload.begin(), payload.end());

            auto hdr = rec.header();
            std::array<std::uint8_t, tls_hdrsize> tls_hdr{};
            tls_hdr[0] = hdr.content_type;
            tls_hdr[1] = static_cast<std::uint8_t>((hdr.version >> 8) & 0xFF);
            tls_hdr[2] = static_cast<std::uint8_t>(hdr.version & 0xFF);
            tls_hdr[3] = static_cast<std::uint8_t>((hdr.length >> 8) & 0xFF);
            tls_hdr[4] = static_cast<std::uint8_t>(hdr.length & 0xFF);

            co_return tls_record{.header = tls_hdr, .payload = std::move(payload_copy)};
        }

        auto decode_restls_payload(
            memory::vector<std::byte> &payload,
            const decode_options &opts,
            std::error_code &ec) -> std::optional<decoded_payload>
        {
            if (payload.size() < auth_hdrlen)
            {
                ec = std::make_error_code(std::errc::protocol_error);
                return std::nullopt;
            }

            const auto record_length = payload.size();

            // 安全：byte buffer 转 uint8_t 以就地处理 Restls payload
            auto *payload_raw = reinterpret_cast<std::uint8_t *>(payload.data());

            std::array<std::uint8_t, appdata_maclen> received_mac{};
            std::memcpy(received_mac.data(), payload_raw, appdata_maclen);

            const std::size_t sample_len = std::min(
                static_cast<std::size_t>(record_length - appdata_offset), std::size_t{32});
            auto plaintext_sample = std::span<const std::uint8_t>(
                payload_raw + appdata_offset, sample_len);

            auto mask = compute_mask(mask_input{
                .secret = opts.secret,
                .server_random = opts.server_random,
                .direction = flow_direction::to_client,
                .counter = opts.counter,
                .plaintext_sample = plaintext_sample});

            xor_with_mask(
                std::span<std::uint8_t>(payload_raw + appdata_lenoff, mask_len),
                mask);

            const std::uint16_t data_len =
                (static_cast<std::uint16_t>(payload_raw[appdata_lenoff]) << 8) |
                payload_raw[appdata_lenoff + 1];
            const std::uint16_t cmd =
                (static_cast<std::uint16_t>(payload_raw[appdata_lenoff + 2]) << 8) |
                payload_raw[appdata_lenoff + 3];

            auto payload_after_mac = std::span<const std::uint8_t>(
                payload_raw + appdata_lenoff, record_length - appdata_lenoff);

            auto expected_mac = compute_auth_mac(auth_mac_input{
                .secret = opts.secret,
                .server_random = opts.server_random,
                .direction = flow_direction::to_client,
                .counter = opts.counter,
                .client_finished = {}, // 读方向无 clientFinished
                .tls_header = opts.tls_header,
                .payload_after_mac = payload_after_mac});

            if (CRYPTO_memcmp(received_mac.data(), expected_mac.data(), appdata_maclen) != 0)
            {
                trace::warn<flt::conn | flt::protocol>("auth_mac verification failed, counter={}", opts.counter);
                ec = std::make_error_code(std::errc::permission_denied);
                return std::nullopt;
            }

            return decoded_payload{.data_len = data_len, .cmd = cmd};
        }
    } // namespace


    restls_transport::restls_transport(
        net::ip::tcp::socket socket,
        restls_handover handover)
        : socket_(std::move(socket))
        , script_(std::move(handover.script))
        , tls_version_(handover.version)
        , write_waiter_(socket_.get_executor())
    {
        write_waiter_.expires_at(std::chrono::steady_clock::time_point::max());

        std::memcpy(secret_.data(), handover.secret.data(), 32);
        std::memcpy(server_random_.data(), handover.server_random.data(), 32);
        client_finished_.assign(handover.client_finished.begin(), handover.client_finished.end());
        if (!handover.initial_data.empty())
        {
            initial_buffer_.assign(handover.initial_data.begin(), handover.initial_data.end());
        }

        trace::debug<flt::conn | flt::protocol>("created, initial_data={}, tls13={}, client_finished={}",
                     handover.initial_data.size(), (handover.version == tls_version::v13), handover.client_finished.size());
    }

    restls_transport::~restls_transport() = default;


    auto restls_transport::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        if (initial_offset_ < initial_buffer_.size())
        {
            const auto available = initial_buffer_.size() - initial_offset_;
            const auto n = std::min(available, buffer.size());
            std::memcpy(buffer.data(), initial_buffer_.data() + initial_offset_, n);
            initial_offset_ += n;
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
            co_return n;
        }

        auto frame_opt = co_await read_restls_frame(ec);
        if (ec || !frame_opt)
        {
            co_return 0;
        }

        // 收到响应帧后，唤醒挂起的 write 协程（解除写阻塞）
        if (write_pending_)
        {
            write_pending_ = false;
            write_waiter_.cancel();
            write_waiter_.expires_at(std::chrono::steady_clock::time_point::max());
        }

        auto &frame = *frame_opt;
        const auto n = std::min(frame.size(), buffer.size());
        std::memcpy(buffer.data(), frame.data(), n);

        if (frame.size() > n)
        {
            pending_buffer_.assign(frame.begin() + n, frame.end());
            pending_offset_ = 0;
        }

        co_return n;
    }

    auto restls_transport::read_restls_frame(std::error_code &ec)
        -> net::awaitable<std::optional<memory::vector<std::byte>>>
    {
        auto record_opt = co_await read_tls_record(socket_, ec);
        if (ec || !record_opt)
        {
            co_return std::nullopt;
        }

        auto &record = *record_opt;

        auto decoded_opt = decode_restls_payload(
            record.payload,
            decode_options{
                .secret = std::span<const std::uint8_t, 32>(secret_),
                .server_random = std::span<const std::uint8_t, 32>(server_random_),
                .counter = read_counter_,
                .tls_header = record.header},
            ec);
        if (ec || !decoded_opt)
        {
            co_return std::nullopt;
        }

        ++read_counter_;

        if (decoded_opt->cmd == cmd_randresp)
        {
            trace::debug<flt::conn | flt::protocol>("received random_response command, count={}", decoded_opt->data_len);
            if (decoded_opt->data_len > 0)
            {
                co_await send_random_response(static_cast<std::uint8_t>(decoded_opt->data_len), ec);
                if (ec)
                {
                    co_return std::nullopt;
                }
            }
            co_return co_await read_restls_frame(ec);
        }

        const std::size_t data_start = appdata_offset;
        const std::size_t data_end = data_start + decoded_opt->data_len;
        if (data_end > record.payload.size())
        {
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        auto &payload = record.payload;
        memory::vector<std::byte> result(payload.begin() + data_start, payload.begin() + data_end);
        trace::debug<flt::conn | flt::protocol>("frame decoded: data_len={}, cmd={}, counter={}",
                     decoded_opt->data_len, decoded_opt->cmd, read_counter_ - 1);
        co_return result;
    }


    auto restls_transport::async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        return write_restls_frame(buffer, ec);
    }

    auto restls_transport::async_write(std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        return write_restls_frame(data, ec);
    }

    auto restls_transport::write_restls_frame(std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        // 等待 write_pending_ 解除（被 async_read_some 收到响应帧后 cancel 唤醒）
        while (write_pending_)
        {
            boost::system::error_code wait_ec;
            co_await write_waiter_.async_wait(
                net::redirect_error(trace::use_prefix_awaitable, wait_ec));
            // 醒来后若 write_pending_ 仍为 true，说明是外部 cancel
            //（tunnel 的 || 操作符 cancel，或 transport 析构），而非 read 端解除
            //（read 端和 close/cancel 都会先设 write_pending_=false 再 cancel timer）
            // 此时必须退出，否则 write 协程永久挂起导致 tunnel 死锁
            if (write_pending_)
            {
                ec = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
        }

        auto alloc = script_.allocate(write_counter_, data.size());

        const auto total_payload = static_cast<std::size_t>(alloc.payload_len);
        memory::vector<std::uint8_t> plaintext(total_payload, 0);

        plaintext[appdata_maclen] = static_cast<std::uint8_t>((alloc.data_len >> 8) & 0xFF);
        plaintext[appdata_maclen + 1] = static_cast<std::uint8_t>(alloc.data_len & 0xFF);

        plaintext[appdata_maclen + 2] = static_cast<std::uint8_t>((static_cast<std::uint16_t>(alloc.cmd) >> 8) & 0xFF);
        plaintext[appdata_maclen + 3] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(alloc.cmd) & 0xFF);

        const auto copy_len = std::min(static_cast<std::size_t>(alloc.data_len), data.size());
        if (copy_len > 0)
        {
            std::memcpy(plaintext.data() + auth_hdrlen, data.data(), copy_len);
        }

        std::size_t remaining = 0;
        if (total_payload > auth_hdrlen)
            remaining = total_payload - auth_hdrlen;
        const std::size_t sample_len = std::min(remaining, std::size_t{32});
        auto plaintext_sample = std::span<const std::uint8_t>(
            plaintext.data() + auth_hdrlen, sample_len);

        auto mask = compute_mask(mask_input{
            .secret = std::span<const std::uint8_t, 32>(secret_),
            .server_random = std::span<const std::uint8_t, 32>(server_random_),
            .direction = flow_direction::to_server,
            .counter = write_counter_,
            .plaintext_sample = plaintext_sample});

        xor_with_mask(
            std::span<std::uint8_t>(plaintext.data() + appdata_maclen, mask_len),
            mask);

        std::array<std::uint8_t, tls_hdrsize> tls_hdr{};
        tls_hdr[0] = content_type_appdata;
        tls_hdr[1] = 0x03;
        tls_hdr[2] = 0x03;
        tls_hdr[3] = static_cast<std::uint8_t>((total_payload >> 8) & 0xFF);
        tls_hdr[4] = static_cast<std::uint8_t>(total_payload & 0xFF);

        auto payload_after_mac = std::span<const std::uint8_t>(
            plaintext.data() + appdata_maclen, total_payload - appdata_maclen);

        auto client_finished_span = std::span<const std::uint8_t>();
        if (first_write_ && !client_finished_.empty())
        {
            client_finished_span = std::span<const std::uint8_t>(client_finished_);
        }

        auto mac = compute_auth_mac(auth_mac_input{
            .secret = std::span<const std::uint8_t, 32>(secret_),
            .server_random = std::span<const std::uint8_t, 32>(server_random_),
            .direction = flow_direction::to_server,
            .counter = write_counter_,
            .client_finished = client_finished_span,
            .tls_header = tls_hdr,
            .payload_after_mac = payload_after_mac});

        std::memcpy(plaintext.data(), mac.data(), appdata_maclen);

        if (first_write_)
        {
            first_write_ = false;
            client_finished_.clear();
        }

        const std::size_t frame_size = tls_hdrsize + total_payload;
        auto frame_rec = ::psm::tls::record::builder()
                             .type(content_type_appdata)
                             .version(0x0303)
                             .payload_u8(std::span<const std::uint8_t>(plaintext.data(), total_payload))
                             .build();
        auto frame_bytes = frame_rec.serialize();

        boost::system::error_code boost_ec;
        co_await net::async_write(
            socket_, net::buffer(frame_bytes.data(), frame_bytes.size()),
            net::redirect_error(trace::use_prefix_awaitable, boost_ec));

        if (boost_ec)
        {
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        ++write_counter_;

        if (alloc.write_blocking)
        {
            write_pending_ = true;
        }

        trace::debug<flt::conn | flt::protocol>("frame sent: data_len={}, payload={}, counter={}",
                     copy_len, total_payload, write_counter_ - 1);
        co_return copy_len;
    }


    auto restls_transport::send_random_response(std::uint8_t count, std::error_code &ec)
        -> net::awaitable<void>
    {
        for (std::uint8_t i = 0; i < count; ++i)
        {
            const auto magic_len = randresp_magic.size();
            const auto payload_len = auth_hdrlen + magic_len;

            memory::vector<std::uint8_t> plaintext(payload_len, 0);

            plaintext[appdata_maclen] = static_cast<std::uint8_t>((magic_len >> 8) & 0xFF);
            plaintext[appdata_maclen + 1] = static_cast<std::uint8_t>(magic_len & 0xFF);
            plaintext[appdata_maclen + 2] = static_cast<std::uint8_t>((cmd_randresp >> 8) & 0xFF);
            plaintext[appdata_maclen + 3] = static_cast<std::uint8_t>(cmd_randresp & 0xFF);

            std::memcpy(plaintext.data() + auth_hdrlen,
                        randresp_magic.data(), magic_len);

            auto sample = std::span<const std::uint8_t>(
                plaintext.data() + auth_hdrlen, magic_len);
            auto mask = compute_mask(mask_input{
                .secret = std::span<const std::uint8_t, 32>(secret_),
                .server_random = std::span<const std::uint8_t, 32>(server_random_),
                .direction = flow_direction::to_client,
                .counter = read_counter_,
                .plaintext_sample = sample});

            xor_with_mask(
                std::span<std::uint8_t>(plaintext.data() + appdata_maclen, mask_len),
                mask);

            std::array<std::uint8_t, tls_hdrsize> tls_hdr{};
            tls_hdr[0] = content_type_appdata;
            tls_hdr[1] = 0x03;
            tls_hdr[2] = 0x03;
            tls_hdr[3] = static_cast<std::uint8_t>((payload_len >> 8) & 0xFF);
            tls_hdr[4] = static_cast<std::uint8_t>(payload_len & 0xFF);

            auto after_mac = std::span<const std::uint8_t>(
                plaintext.data() + appdata_maclen, payload_len - appdata_maclen);
            auto mac = compute_auth_mac(auth_mac_input{
                .secret = std::span<const std::uint8_t, 32>(secret_),
                .server_random = std::span<const std::uint8_t, 32>(server_random_),
                .direction = flow_direction::to_client,
                .counter = read_counter_,
                .client_finished = {},
                .tls_header = tls_hdr,
                .payload_after_mac = after_mac});

            std::memcpy(plaintext.data(), mac.data(), appdata_maclen);

            auto frame_rec = ::psm::tls::record::builder()
                                 .type(content_type_appdata)
                                 .version(0x0303)
                                 .payload_u8(std::span<const std::uint8_t>(plaintext.data(), payload_len))
                                 .build();
            auto frame_bytes = frame_rec.serialize();

            boost::system::error_code boost_ec;
            co_await net::async_write(
                socket_, net::buffer(frame_bytes.data(), frame_bytes.size()),
                net::redirect_error(trace::use_prefix_awaitable, boost_ec));

            if (boost_ec)
            {
                ec = std::make_error_code(std::errc::connection_reset);
                co_return;
            }

            ++read_counter_;
        }
    }


    void restls_transport::close()
    {
        write_pending_ = false;
        write_waiter_.cancel();
        boost::system::error_code ec;
        socket_.close(ec);
    }

    void restls_transport::cancel()
    {
        write_pending_ = false;
        write_waiter_.cancel();
        socket_.cancel();
    }
} // namespace psm::stealth::restls
