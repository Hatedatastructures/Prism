/**
 * @file transport.cpp
 * @brief Restls 传输层实现（中间人代理模式）
 * @details 在 raw TCP transport 之上处理 Restls app data 帧的嵌入和提取。
 * read 方向通过 common::read_tls_frame 读取完整 TLS record，验证 type=0x17，
 * 验证 authMac、XOR 解码、提取 data。
 * write 方向构造 [TLS Header 5B][authMac 8B][masked_len 2B][masked_cmd 2B][data][padding]，
 * 再通过 reliable transport 写出。
 */

#include <prism/stealth/facade/restls/transport.hpp>

#include <prism/core/memory/container.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/stealth/common.hpp>
#include <prism/stealth/facade/restls/crypto.hpp>
#include <prism/trace/trace.hpp>

#include <algorithm>
#include <cstring>

using namespace psm::trace;

namespace psm::stealth::restls
{

    namespace
    {

        /// 用 mask 对 4 字节 [dataLen(2B)+command(2B)] 做就地 XOR
        inline auto xor_len_cmd(std::uint8_t *dst, std::span<const std::uint8_t> mask) noexcept -> void
        {
            for (std::size_t i = 0; i < 4; ++i)
                dst[i] ^= mask[i % mask.size()];
        }

    } // namespace


    restls_transport::restls_transport(
        std::shared_ptr<transport::reliable> raw_trans,
        restls_handover handover)
        : raw_trans_(std::move(raw_trans)),
          secret_(),
          server_random_(),
          script_(std::move(handover.script)),
          tls_version_(handover.version),
          client_finished_(std::move(handover.client_finished)),
          write_waiter_(raw_trans_->executor())
    {
        std::memcpy(secret_.data(), handover.secret.data(), 32);
        std::memcpy(server_random_.data(), handover.server_random.data(), 32);
        write_waiter_.expires_at(std::chrono::steady_clock::time_point::max());
    }


    restls_transport::~restls_transport() noexcept = default;


    auto restls_transport::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        if (pending_offset_ < pending_buffer_.size())
        {
            const auto remaining = pending_buffer_.size() - pending_offset_;
            const auto to_copy = std::min(remaining, buffer.size());
            std::memcpy(buffer.data(), pending_buffer_.data() + pending_offset_, to_copy);
            pending_offset_ += to_copy;
            if (pending_offset_ >= pending_buffer_.size())
            {
                pending_buffer_.clear();
                pending_offset_ = 0;
            }
            co_return to_copy;
        }

        auto frame_opt = co_await read_restls_frame(ec);
        if (ec || !frame_opt)
            co_return 0;

        auto &frame = *frame_opt;
        const auto to_copy = std::min(frame.size(), buffer.size());
        std::memcpy(buffer.data(), frame.data(), to_copy);

        if (to_copy < frame.size())
        {
            pending_buffer_.assign(frame.begin() + static_cast<std::ptrdiff_t>(to_copy), frame.end());
            pending_offset_ = 0;
        }

        if (write_pending_)
        {
            write_pending_ = false;
            write_waiter_.cancel();
            write_waiter_.expires_at(std::chrono::steady_clock::time_point::max());
        }

        co_return to_copy;
    }


    auto restls_transport::async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        while (write_pending_)
        {
            boost::system::error_code wait_ec;
            co_await write_waiter_.async_wait(
                net::redirect_error(trace::use_prefix_awaitable, wait_ec));
            if (wait_ec && wait_ec != net::error::operation_aborted)
            {
                ec = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
        }

        auto written = co_await write_restls_frame(buffer, ec);
        co_return ec ? 0 : written;
    }


    auto restls_transport::read_restls_frame(std::error_code &ec)
        -> net::awaitable<std::optional<memory::vector<std::byte>>>
    {
        ec.clear();

        // 直接读 client→server 方向的下一个 TLS record
        auto &socket = raw_trans_->native_socket();
        auto frame_opt = co_await common::read_tls_frame(socket, ec);
        if (ec || !frame_opt)
            co_return std::nullopt;

        memory::vector<std::byte> frame = std::move(*frame_opt);

        if (frame.size() < tls_hdrsize + auth_hdrlen)
        {
            trace::warn<flt::conn | flt::protocol>(
                "restls read_frame: frame too short, size={}", frame.size());
            ec = std::make_error_code(std::errc::bad_message);
            co_return std::nullopt;
        }

        auto *record = reinterpret_cast<std::uint8_t *>(frame.data());
        if (record[0] != 0x17)
        {
            trace::warn<flt::conn | flt::protocol>(
                "restls read_frame: not ApplicationData record, type={:#x}", record[0]);
            ec = std::make_error_code(std::errc::bad_message);
            co_return std::nullopt;
        }

        const auto payload_len = frame.size() - tls_hdrsize;
        auto *payload = record + tls_hdrsize;

        // 构造 authMac 计算所需的 TLS header span（5B record header）
        const auto tls_header_span = std::span<const std::uint8_t>(record, tls_hdrsize);

        // 首次 c2s authMac 需要拼接 client_finished
        std::span<const std::uint8_t> cf_span;
        if (!client_finished_.empty())
        {
            cf_span = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(client_finished_.data()),
                client_finished_.size());
        }

        auto auth_mac = compute_auth_mac(auth_mac_input{
            .secret = std::span<const std::uint8_t, 32>(secret_),
            .server_random = std::span<const std::uint8_t, 32>(server_random_),
            .direction = flow_direction::to_server,
            .counter = to_server_counter_,
            .client_finished = cf_span,
            .tls_header = tls_header_span,
            .payload_after_mac = std::span<const std::uint8_t>(
                payload + appdata_maclen, payload_len - appdata_maclen),
        });

        if (std::memcmp(payload, auth_mac.data(), appdata_maclen) != 0)
        {
            // 容错：SingMux 可能在 c.Write([]byte{}) 时隐含递增 restlsToServerCounter，
            // 导致客户端/服务端 counter 产生偏移。
            // 暴力搜索 counter（±5 范围），找到匹配值。
            bool recovered = false;
            for (int delta = -5; delta <= 5; ++delta)
            {
                if (delta == 0) continue;
                const auto alt_counter = static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(to_server_counter_) + delta);
                auto alt_mac = compute_auth_mac(auth_mac_input{
                    .secret = std::span<const std::uint8_t, 32>(secret_),
                    .server_random = std::span<const std::uint8_t, 32>(server_random_),
                    .direction = flow_direction::to_server,
                    .counter = alt_counter,
                    .client_finished = cf_span,
                    .tls_header = tls_header_span,
                    .payload_after_mac = std::span<const std::uint8_t>(
                        payload + appdata_maclen, payload_len - appdata_maclen),
                });
                if (std::memcmp(payload, alt_mac.data(), appdata_maclen) == 0)
                {
                    trace::warn<flt::conn | flt::protocol>(
                        "restls read_frame: counter corrected {}→{} (delta={:+d})",
                        to_server_counter_, alt_counter, delta);
                    to_server_counter_ = alt_counter;
                    auth_mac = alt_mac;
                    recovered = true;
                    break;
                }
            }
            if (!recovered)
            {
                // payload_len <= 30 是 TLS 1.3 加密 alert（close_notify = 2B+1B+16B=19B）
                // 客户端收到后端 NewSessionTicket 后 restlsAuthed 解析失败 → 发 close_notify
                // 不报错也不递归，直接返回 nullopt（EOF）
                if (payload_len <= 30)
                {
                    trace::debug<flt::conn | flt::protocol>(
                        "restls read_frame: ignoring likely TLS alert (payload_len={}), treating as EOF",
                        payload_len);
                    co_return std::nullopt;
                }
                trace::warn<flt::conn | flt::protocol>(
                    "restls read_frame: auth_mac mismatch: counter={}, payload_len={}",
                    to_server_counter_, payload_len);
                ec = std::make_error_code(std::errc::bad_message);
                co_return std::nullopt;
            }
        }

        // authMac 验证通过，重置跳过计数
        skip_count_ = 0;

        auto mask = compute_mask(mask_input{
            .secret = std::span<const std::uint8_t, 32>(secret_),
            .server_random = std::span<const std::uint8_t, 32>(server_random_),
            .direction = flow_direction::to_server,
            .counter = to_server_counter_,
            .plaintext_sample = std::span<const std::uint8_t>(payload + appdata_offset,
                std::min<std::size_t>(32, payload_len - appdata_offset)),
        });

        xor_len_cmd(payload + appdata_lenoff, mask);

        std::uint16_t data_len = (static_cast<std::uint16_t>(payload[appdata_lenoff]) << 8) |
                                 static_cast<std::uint16_t>(payload[appdata_lenoff + 1]);
        std::uint8_t  cmd_type = payload[appdata_lenoff + 2];
        std::uint8_t  cmd_arg  = payload[appdata_lenoff + 3];

        ++to_server_counter_;
        ++read_counter_;

        // 首次 c2s 消费完 client_finished
        if (!client_finished_.empty())
            client_finished_.clear();

        if (data_len > payload_len - appdata_offset)
        {
            trace::warn<flt::conn | flt::protocol>(
                "restls read_frame: data_len={} exceeds payload={}", data_len, payload_len - appdata_offset);
            ec = std::make_error_code(std::errc::bad_message);
            co_return std::nullopt;
        }

        memory::vector<std::byte> data(data_len, memory::current_resource());
        std::memcpy(data.data(), payload + appdata_offset, data_len);

        // ActResponse(cmd_type=0x01)：回 cmd_arg 个 random-response 帧给客户端
        if (cmd_type == cmd_type_response && cmd_arg > 0)
        {
            std::error_code resp_ec;
            co_await send_random_response(cmd_arg, resp_ec);
        }

        trace::debug<flt::conn | flt::protocol>(
            "restls read_frame: data_len={}, cmd_type={}, cmd_arg={}, to_srv_ctr={}",
            data_len, cmd_type, cmd_arg, to_server_counter_);

        co_return data;
    }


    auto restls_transport::write_restls_frame(std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        auto alloc = script_.allocate(write_counter_, data.size());

        const auto data_len = data.size();
        const auto padding_len = (alloc.data_len > data_len) ? (alloc.data_len - data_len) : 0;
        const auto payload_size = auth_hdrlen + data_len + padding_len;

        memory::vector<std::uint8_t> record(tls_hdrsize + payload_size, memory::current_resource());
        auto *record_data = record.data();

        // 写入 TLS 1.3 ApplicationData record header
        record_data[0] = 0x17;
        record_data[1] = 0x03;
        record_data[2] = 0x03;
        record_data[3] = static_cast<std::uint8_t>((payload_size >> 8) & 0xFF);
        record_data[4] = static_cast<std::uint8_t>(payload_size & 0xFF);

        auto *payload = record_data + tls_hdrsize;

        // 写入明文 masked_len + masked_cmd（根据 script 决定 command 类型）
        payload[appdata_lenoff] = static_cast<std::uint8_t>((data_len >> 8) & 0xFF);
        payload[appdata_lenoff + 1] = static_cast<std::uint8_t>(data_len & 0xFF);
        if (alloc.cmd == command_type::response)
        {
            payload[appdata_lenoff + 2] = cmd_type_response;
            payload[appdata_lenoff + 3] = alloc.response_count;
        }
        else
        {
            payload[appdata_lenoff + 2] = cmd_type_noop;
            payload[appdata_lenoff + 3] = 0;
        }

        std::memcpy(payload + appdata_offset,
                    reinterpret_cast<const std::uint8_t *>(data.data()), data_len);

        if (padding_len > 0)
            std::memset(payload + appdata_offset + data_len, 0, padding_len);

        // 计算 mask（基于明文 data 区域）
        auto mask = compute_mask(mask_input{
            .secret = std::span<const std::uint8_t, 32>(secret_),
            .server_random = std::span<const std::uint8_t, 32>(server_random_),
            .direction = flow_direction::to_client,
            .counter = to_client_counter_,
            .plaintext_sample = std::span<const std::uint8_t>(payload + appdata_offset,
                std::min<std::size_t>(32, payload_size - appdata_offset)),
        });

        xor_len_cmd(payload + appdata_lenoff, mask);

        // 计算 authMac（基于完整 record）
        auto auth_mac = compute_auth_mac(auth_mac_input{
            .secret = std::span<const std::uint8_t, 32>(secret_),
            .server_random = std::span<const std::uint8_t, 32>(server_random_),
            .direction = flow_direction::to_client,
            .counter = to_client_counter_,
            .client_finished = {},
            .tls_header = std::span<const std::uint8_t>(record_data, tls_hdrsize),
            .payload_after_mac = std::span<const std::uint8_t>(payload + appdata_maclen,
                payload_size - appdata_maclen),
        });

        std::memcpy(payload, auth_mac.data(), appdata_maclen);

        // 通过 reliable transport 写入完整 TLS record
        auto written = co_await transport::async_write(
            *raw_trans_,
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(record_data), record.size()),
            ec);
        if (ec)
        {
            trace::warn<flt::conn | flt::protocol>(
                "restls write_frame: write failed, ec={}", ec.message());
            co_return 0;
        }

        ++to_client_counter_;
        ++write_counter_;

        if (alloc.write_blocking)
            write_pending_ = true;

        trace::debug<flt::conn | flt::protocol>(
            "restls write_frame: data_len={}, payload={}, to_cli_ctr={}, blocking={}",
            data_len, payload_size, to_client_counter_, alloc.write_blocking);

        co_return data_len;
    }


    auto restls_transport::send_random_response(std::uint8_t count, std::error_code &ec)
        -> net::awaitable<void>
    {
        ec.clear();
        for (std::uint8_t i = 0; i < count; ++i)
        {
            memory::vector<std::byte> randresp(randresp_magic.size(), memory::current_resource());
            std::memcpy(randresp.data(),
                        reinterpret_cast<const std::byte *>(randresp_magic.data()),
                        randresp_magic.size());
            co_await write_restls_frame(randresp, ec);
            if (ec)
                co_return;
        }
    }


    void restls_transport::close()
    {
        if (raw_trans_)
            raw_trans_->close();
        write_waiter_.cancel();
    }


    void restls_transport::cancel()
    {
        if (raw_trans_)
            raw_trans_->cancel();
        write_waiter_.cancel();
    }

} // namespace psm::stealth::restls
