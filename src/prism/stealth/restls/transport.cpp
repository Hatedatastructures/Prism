#include <prism/stealth/restls/transport.hpp>
#include <prism/stealth/common.hpp>
#include <prism/trace.hpp>

#include <algorithm>
#include <cstring>

#include <openssl/crypto.h>

namespace psm::stealth::restls
{
    namespace
    {
        constexpr std::string_view tag = "[Restls.Transport]";
    } // namespace

    // ═══════════════════════════════════════════════════════════
    // 构造/析构
    // ═══════════════════════════════════════════════════════════

    restls_transport::restls_transport(
        net::ip::tcp::socket socket,
        restls_handover handover)
        : socket_(std::move(socket))
        , script_(std::move(handover.script))
        , tls13_(handover.version == tls_version::v13)
        , tls_version_(handover.version)
    {
        std::memcpy(secret_.data(), handover.secret.data(), 32);
        std::memcpy(server_random_.data(), handover.server_random.data(), 32);
        client_finished_.assign(handover.client_finished.begin(), handover.client_finished.end());
        if (!handover.initial_data.empty())
        {
            initial_buffer_.assign(handover.initial_data.begin(), handover.initial_data.end());
        }
        trace::debug("{} created, initial_data={}, tls13={}, client_finished={}",
                     tag, handover.initial_data.size(), (handover.version == tls_version::v13), handover.client_finished.size());
    }

    restls_transport::~restls_transport() = default;

    // ═══════════════════════════════════════════════════════════
    // 读取方向
    // ═══════════════════════════════════════════════════════════

    auto restls_transport::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        // 优先返回初始数据
        if (initial_offset_ < initial_buffer_.size())
        {
            const auto available = initial_buffer_.size() - initial_offset_;
            const auto n = std::min(available, buffer.size());
            std::memcpy(buffer.data(), initial_buffer_.data() + initial_offset_, n);
            initial_offset_ += n;
            co_return n;
        }

        // 返回 pending buffer
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

        // 读取新的 Restls frame
        auto frame_opt = co_await read_restls_frame(ec);
        if (ec || !frame_opt)
        {
            co_return 0;
        }

        auto &frame = *frame_opt;
        const auto n = std::min(frame.size(), buffer.size());
        std::memcpy(buffer.data(), frame.data(), n);

        if (frame.size() > n)
        {
            pending_buffer_.assign(frame.begin() + n, frame.end());
            pending_offset_ = 0;
        }

        // 如果 write_blocking 且收到数据，解除写阻塞
        if (write_pending_ && n > 0)
        {
            write_pending_ = false;
            if (!send_buf_.empty())
            {
                auto flush_data = std::move(send_buf_);
                send_buf_.clear();
                co_await write_restls_frame(flush_data, ec);
            }
        }

        co_return n;
    }

    auto restls_transport::read_restls_frame(std::error_code &ec)
        -> net::awaitable<std::optional<memory::vector<std::byte>>>
    {
        boost::system::error_code boost_ec;

        // 读取 TLS header (5 bytes)
        std::array<std::byte, tls_hdrsize> header{};
        auto header_n = co_await net::async_read(
            socket_, net::buffer(header.data(), tls_hdrsize),
            net::redirect_error(net::use_awaitable, boost_ec));

        if (boost_ec || header_n < tls_hdrsize)
        {
            ec = std::make_error_code(std::errc::connection_reset);
            co_return std::nullopt;
        }

        // safe: casting byte buffer to uint8_t to parse TLS record header fields
        const auto *raw = reinterpret_cast<const std::uint8_t *>(header.data());
        if (raw[0] != content_appdata)
        {
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        const std::uint16_t record_length =
            (static_cast<std::uint16_t>(raw[3]) << 8) | raw[4];

        // 读取 TLS payload
        memory::vector<std::byte> payload(record_length);
        auto payload_n = co_await net::async_read(
            socket_, net::buffer(payload.data(), record_length),
            net::redirect_error(net::use_awaitable, boost_ec));

        if (boost_ec || payload_n < record_length)
        {
            ec = std::make_error_code(std::errc::connection_reset);
            co_return std::nullopt;
        }

        // 验证最小长度：auth_mac(8) + masked_len(2) + masked_cmd(2) = 12
        if (payload.size() < auth_hdrlen)
        {
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        // safe: casting mutable byte buffer to uint8_t for in-place Restls payload processing
        auto *payload_raw = reinterpret_cast<std::uint8_t *>(payload.data());

        // 保存 TLS header 用于 auth_mac 验证
        std::array<std::uint8_t, tls_hdrsize> tls_hdr{};
        std::memcpy(tls_hdr.data(), raw, tls_hdrsize);

        // 1. 提取 auth_mac (bytes 0-7)
        std::array<std::uint8_t, appdata_maclen> received_mac{};
        std::memcpy(received_mac.data(), payload_raw, appdata_maclen);

        // 2. 计算 mask（基于明文，从 offset 12 开始的数据，最多 32 字节）
        // 注意：此时 masked_len/masked_cmd 还未解码
        // mask 输入使用的是 XOR 之前的明文数据（即 offset 12 之后的内容）
        const std::size_t sample_len = std::min(
            static_cast<std::size_t>(record_length - appdata_offset), std::size_t{32});
        auto plaintext_sample = std::span<const std::uint8_t>(
            payload_raw + appdata_offset, sample_len);

        auto mask = compute_mask(mask_input{
            .secret = std::span<const std::uint8_t, 32>(secret_),
            .server_random = std::span<const std::uint8_t, 32>(server_random_),
            .direction = flow_direction::to_client,
            .counter = read_counter_,
            .plaintext_sample = plaintext_sample});

        // 3. XOR 解码 masked_len 和 masked_cmd (bytes 8-11)
        xor_with_mask(
            std::span<std::uint8_t>(payload_raw + appdata_lenoff, mask_len),
            mask);

        // 4. 提取解码后的 data_len 和 cmd
        const std::uint16_t data_len =
            (static_cast<std::uint16_t>(payload_raw[appdata_lenoff]) << 8) |
            payload_raw[appdata_lenoff + 1];
        const std::uint16_t cmd =
            (static_cast<std::uint16_t>(payload_raw[appdata_lenoff + 2]) << 8) |
            payload_raw[appdata_lenoff + 3];

        // 5. 验证 auth_mac
        auto payload_after_mac = std::span<const std::uint8_t>(
            payload_raw + appdata_lenoff, record_length - appdata_lenoff);

        auto expected_mac = compute_auth_mac(auth_mac_input{
            .secret = std::span<const std::uint8_t, 32>(secret_),
            .server_random = std::span<const std::uint8_t, 32>(server_random_),
            .direction = flow_direction::to_client,
            .counter = read_counter_,
            .client_finished = {}, // no clientFinished in read direction
            .tls_header = tls_hdr,
            .payload_after_mac = payload_after_mac});

        if (CRYPTO_memcmp(received_mac.data(), expected_mac.data(), appdata_maclen) != 0)
        {
            trace::warn("{} auth_mac verification failed, counter={}", tag, read_counter_);
            ec = std::make_error_code(std::errc::permission_denied);
            co_return std::nullopt;
        }

        ++read_counter_;

        // 6. 处理随机响应命令
        if (cmd == cmd_randresp)
        {
            trace::debug("{} received random_response command, count={}", tag, data_len);
            // data_len 被复用为响应请求数量
            if (data_len > 0)
            {
                co_await send_random_response(static_cast<std::uint8_t>(data_len), ec);
                if (ec)
                {
                    co_return std::nullopt;
                }
            }
            // 随机响应不是用户数据，继续读下一帧
            co_return co_await read_restls_frame(ec);
        }

        // 7. 提取用户数据
        const std::size_t data_start = appdata_offset;
        const std::size_t data_end = data_start + data_len;
        if (data_end > payload.size())
        {
            ec = std::make_error_code(std::errc::protocol_error);
            co_return std::nullopt;
        }

        memory::vector<std::byte> result(payload.begin() + data_start, payload.begin() + data_end);
        trace::debug("{} frame decoded: data_len={}, cmd={}, counter={}", tag, data_len, cmd, read_counter_ - 1);
        co_return result;
    }

    // ═══════════════════════════════════════════════════════════
    // 写入方向
    // ═══════════════════════════════════════════════════════════

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

        // 写阻塞时缓冲数据
        if (write_pending_)
        {
            send_buf_.insert(send_buf_.end(), data.begin(), data.end());
            co_return data.size();
        }

        // 1. script 分配
        auto alloc = script_.allocate(write_counter_, data.size());

        // 2. 构造明文 payload
        // 布局：[zeros(8)][data_len(2B BE)][cmd(2B)][data][padding]
        const auto total_payload = static_cast<std::size_t>(alloc.payload_len);
        memory::vector<std::uint8_t> plaintext(total_payload, 0);

        // 写入 data_len (big-endian) at offset 8
        plaintext[appdata_maclen] = static_cast<std::uint8_t>((alloc.data_len >> 8) & 0xFF);
        plaintext[appdata_maclen + 1] = static_cast<std::uint8_t>(alloc.data_len & 0xFF);

        // 写入 cmd at offset 10
        plaintext[appdata_maclen + 2] = static_cast<std::uint8_t>((static_cast<std::uint16_t>(alloc.cmd) >> 8) & 0xFF);
        plaintext[appdata_maclen + 3] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(alloc.cmd) & 0xFF);

        // 写入用户数据 at offset 12
        const auto copy_len = std::min(static_cast<std::size_t>(alloc.data_len), data.size());
        if (copy_len > 0)
        {
            std::memcpy(plaintext.data() + auth_hdrlen, data.data(), copy_len);
        }

        // 3. 计算 mask（基于明文数据，从 offset 12 开始，最多 32 字节）
        const std::size_t sample_len = std::min(
            total_payload > auth_hdrlen ? total_payload - auth_hdrlen : std::size_t{0},
            std::size_t{32});
        auto plaintext_sample = std::span<const std::uint8_t>(
            plaintext.data() + auth_hdrlen, sample_len);

        auto mask = compute_mask(mask_input{
            .secret = std::span<const std::uint8_t, 32>(secret_),
            .server_random = std::span<const std::uint8_t, 32>(server_random_),
            .direction = flow_direction::to_server,
            .counter = write_counter_,
            .plaintext_sample = plaintext_sample});

        // 4. XOR masked_len 和 masked_cmd (offset 8-11)
        xor_with_mask(
            std::span<std::uint8_t>(plaintext.data() + appdata_maclen, mask_len),
            mask);

        // 5. 构造 TLS header
        std::array<std::uint8_t, tls_hdrsize> tls_hdr{};
        tls_hdr[0] = content_appdata;
        tls_hdr[1] = 0x03;
        tls_hdr[2] = 0x03;
        tls_hdr[3] = static_cast<std::uint8_t>((total_payload >> 8) & 0xFF);
        tls_hdr[4] = static_cast<std::uint8_t>(total_payload & 0xFF);

        // 6. 计算 auth_mac
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

        // 7. 写入 auth_mac 到 plaintext offset 0-7
        std::memcpy(plaintext.data(), mac.data(), appdata_maclen);

        // 首次写入后清除 clientFinished
        if (first_write_)
        {
            first_write_ = false;
            client_finished_.clear();
        }

        // 8. 发送完整 TLS record
        const std::size_t frame_size = tls_hdrsize + total_payload;
        memory::vector<std::byte> frame(frame_size);
        std::memcpy(frame.data(), tls_hdr.data(), tls_hdrsize);
        std::memcpy(frame.data() + tls_hdrsize, plaintext.data(), total_payload);

        boost::system::error_code boost_ec;
        co_await net::async_write(
            socket_, net::buffer(frame.data(), frame.size()),
            net::redirect_error(net::use_awaitable, boost_ec));

        if (boost_ec)
        {
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        ++write_counter_;

        // 9. 写阻塞
        if (alloc.write_blocking)
        {
            write_pending_ = true;
        }

        trace::debug("{} frame sent: data_len={}, payload={}, counter={}",
                     tag, copy_len, total_payload, write_counter_ - 1);
        co_return copy_len;
    }

    // ═══════════════════════════════════════════════════════════
    // 随机响应
    // ═══════════════════════════════════════════════════════════

    auto restls_transport::send_random_response(std::uint8_t count, std::error_code &ec)
        -> net::awaitable<void>
    {
        for (std::uint8_t i = 0; i < count; ++i)
        {
            // 构造随机响应帧
            const auto magic_len = randresp_magic.size();
            const auto payload_len = auth_hdrlen + magic_len;

            memory::vector<std::uint8_t> plaintext(payload_len, 0);

            // data_len = magic_len
            plaintext[appdata_maclen] = static_cast<std::uint8_t>((magic_len >> 8) & 0xFF);
            plaintext[appdata_maclen + 1] = static_cast<std::uint8_t>(magic_len & 0xFF);
            // cmd = random_response
            plaintext[appdata_maclen + 2] = static_cast<std::uint8_t>((cmd_randresp >> 8) & 0xFF);
            plaintext[appdata_maclen + 3] = static_cast<std::uint8_t>(cmd_randresp & 0xFF);

            // 写入 magic 字符串
            std::memcpy(plaintext.data() + auth_hdrlen,
                        randresp_magic.data(), magic_len);

            // 计算 mask
            auto sample = std::span<const std::uint8_t>(
                plaintext.data() + auth_hdrlen, magic_len);
            auto mask = compute_mask(mask_input{
                .secret = std::span<const std::uint8_t, 32>(secret_),
                .server_random = std::span<const std::uint8_t, 32>(server_random_),
                .direction = flow_direction::to_client,
                .counter = read_counter_,
                .plaintext_sample = sample});

            // XOR
            xor_with_mask(
                std::span<std::uint8_t>(plaintext.data() + appdata_maclen, mask_len),
                mask);

            // TLS header
            std::array<std::uint8_t, tls_hdrsize> tls_hdr{};
            tls_hdr[0] = content_appdata;
            tls_hdr[1] = 0x03;
            tls_hdr[2] = 0x03;
            tls_hdr[3] = static_cast<std::uint8_t>((payload_len >> 8) & 0xFF);
            tls_hdr[4] = static_cast<std::uint8_t>(payload_len & 0xFF);

            // auth_mac
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

            // 发送
            const std::size_t frame_size = tls_hdrsize + payload_len;
            memory::vector<std::byte> frame(frame_size);
            std::memcpy(frame.data(), tls_hdr.data(), tls_hdrsize);
            std::memcpy(frame.data() + tls_hdrsize, plaintext.data(), payload_len);

            boost::system::error_code boost_ec;
            co_await net::async_write(
                socket_, net::buffer(frame.data(), frame.size()),
                net::redirect_error(net::use_awaitable, boost_ec));

            if (boost_ec)
            {
                ec = std::make_error_code(std::errc::connection_reset);
                co_return;
            }

            ++read_counter_;
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 连接管理
    // ═══════════════════════════════════════════════════════════

    void restls_transport::close()
    {
        boost::system::error_code ec;
        socket_.close(ec);
    }

    void restls_transport::cancel()
    {
        socket_.cancel();
    }
} // namespace psm::stealth::restls
