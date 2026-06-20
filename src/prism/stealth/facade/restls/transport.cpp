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
#include <cstdlib>
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

        /// 将字节序列格式化为 hex 字符串（仅 debug 用）
        inline auto to_hex_string(const std::uint8_t *data, std::size_t len) -> memory::string
        {
            static constexpr auto hexd = "0123456789abcdef";
            memory::string s;
            s.reserve(len * 2);
            for (std::size_t i = 0; i < len; ++i)
            {
                s.push_back(hexd[data[i] >> 4]);
                s.push_back(hexd[data[i] & 0xf]);
            }
            return s;
        }

        /// 判断是否启用 restls debug 日志
        inline auto restls_debug_enabled() noexcept -> bool
        {
            return std::getenv("PRISM_RESTLS_DEBUG") != nullptr;
        }

    } // namespace


    restls_transport::restls_transport(
        transport::shared_transmission raw_trans,
        restls_handover handover)
        : raw_trans_(std::move(raw_trans)),
          secret_(),
          server_random_(),
          script_(std::move(handover.script)),
          tls_version_(handover.version),
          client_finished_(std::move(handover.client_finished)),
          write_waiter_(raw_trans_->executor()),
          write_signal_(raw_trans_->executor())
    {
        std::memcpy(secret_.data(), handover.secret.data(), 32);
        std::memcpy(server_random_.data(), handover.server_random.data(), 32);
        write_waiter_.expires_at(std::chrono::steady_clock::time_point::max());
        write_signal_.expires_at(std::chrono::steady_clock::time_point::max());

        // DEBUG: dump 连接级密钥参数（受环境变量 PRISM_RESTLS_DEBUG 控制，仅构造时一次）
        if (restls_debug_enabled())
        {
            const auto secret_hex = to_hex_string(secret_.data(), secret_.size());
            const auto sr_hex = to_hex_string(server_random_.data(), server_random_.size());
            const auto cf_hex = to_hex_string(
                reinterpret_cast<const std::uint8_t *>(client_finished_.data()),
                client_finished_.size());
            trace::info<flt::conn | flt::protocol>(
                "[DBG] restls_transport init: secret={} server_random={} client_finished_len={} "
                "client_finished_hex={}",
                secret_hex, sr_hex, client_finished_.size(), cf_hex);
        }
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

        // write_pending_ 的清除已移入 read_restls_frame 循环内，
        // 每读到一个 client 帧（含 magic 空帧）就立即清除，
        // 避免 read 递归时 writer 协程死等。

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

        // while 循环而非递归：每读到一帧都立即清除 write_pending_（对应 mihomo
        // conn.go:842 restlsWritePending.Swap(false)），避免收到 magic 空帧时
        // 递归阻塞下一帧导致 write_pending_ 永不清除、writer 协程死等。
        while (true)
        {
        // 直接从裸 TCP socket 读取 client→server 方向的下一个 TLS record
        // 不能通过 *raw_trans_ 读取：raw_trans_ 包含 preview/snapshot 装饰器层，
        // preview 层仍持有识别阶段预读的 ClientHello（type=0x16），
        // 会导致第一个读到的 frame 是 handshake 而非 ApplicationData。
        auto *rel = raw_trans_->lowest_layer<transport::reliable>();
        if (!rel)
        {
            ec = std::make_error_code(std::errc::not_connected);
            co_return std::nullopt;
        }
        auto &socket = rel->native_socket();
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
                // authMac 校验失败且 counter 容错搜索未恢复。
                // 此前曾基于 payload_len<=30 猜测为客户端 TLS close_notify 并主动 abort，
                // 但 sing-mux 流控/ping/ack 等合法小帧也会落在此范围，
                // 导致大块下行途中一旦出现 counter 失步的小帧即被误判为 close_notify，
                // 连接被错误关闭（apple/github HTTPS 失败的根因）。
                // 后端 NewSessionTicket 已由转发拦截消除（commit 66ed663），
                // 客户端不再会因此发 raw TLS alert，此兜底分支不再必要。
                // 统一走 bad_message：若客户端确在关闭，上层 SS2022/mux 自然会 abort。
                trace::warn<flt::conn | flt::protocol>(
                    "restls read_frame: auth_mac mismatch: counter={}, payload_len={}",
                    to_server_counter_, payload_len);
                ec = std::make_error_code(std::errc::bad_message);
                co_return std::nullopt;
            }
        }

        // authMac 验证通过，重置跳过计数
        skip_count_ = 0;

        const auto c2s_sample_len = std::min<std::size_t>(32, payload_len - appdata_offset);
        auto mask = compute_mask(mask_input{
            .secret = std::span<const std::uint8_t, 32>(secret_),
            .server_random = std::span<const std::uint8_t, 32>(server_random_),
            .direction = flow_direction::to_server,
            .counter = to_server_counter_,
            .plaintext_sample = std::span<const std::uint8_t>(payload + appdata_offset,
                c2s_sample_len),
        });

        // DEBUG: dump c→s mask 输入/输出
        if (restls_debug_enabled())
        {
            const auto sample_hex = to_hex_string(payload + appdata_offset, c2s_sample_len);
            const auto mask_hex = to_hex_string(mask.data(), mask.size());
            const auto pload_hex = to_hex_string(payload + appdata_maclen, payload_len - appdata_maclen);
            const auto cf_hex_part = cf_span.empty()
                ? memory::string("(none)")
                : to_hex_string(cf_span.data(), cf_span.size());
            trace::info<flt::conn | flt::protocol>(
                "[DBG] c2s verify: ctr={} cf_len={} cf_hex={} "
                "tls_hdr={} pload_after_mac={} sample_hex={} mask_hex={}",
                to_server_counter_, cf_span.size(), cf_hex_part,
                to_hex_string(record, tls_hdrsize), pload_hex, sample_hex, mask_hex);
        }

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

        // 收到 client 任意 restls 帧后解除 write blocking。
        // 对应 mihomo conn.go:842 c.restlsWritePending.Swap(false) —
        // 包括 magic 空帧在内，任意 client 帧到达都意味着对端已收到我们的上一帧，
        // script 的 `<N` 阻塞语义解除，writer 协程可以继续。
        if (write_pending_)
        {
            write_pending_ = false;
            write_waiter_.cancel();
            write_waiter_.expires_at(std::chrono::steady_clock::time_point::max());
        }

        // data_len=0 的空帧（ActNoop 心跳/magic response）：不返回上层，loop 读下一帧
        if (data_len == 0)
        {
            trace::debug<flt::conn | flt::protocol>(
                "restls read_frame: empty frame (data_len=0), write_pending_ cleared, continue");
            continue;
        }

        trace::debug<flt::conn | flt::protocol>(
            "restls read_frame: data_len={}, cmd_type={}, cmd_arg={}, to_srv_ctr={}, transport={}",
            data_len, cmd_type, cmd_arg, to_server_counter_,
            reinterpret_cast<void*>(this));

        co_return data;
        } // end while (true)
    }


    auto restls_transport::acquire_write_lock() -> net::awaitable<void>
    {
        // CAS 自旋：成功交换为 true 表示获得锁；否则等待 write_signal_ 被唤醒后重试
        while (write_busy_.exchange(true, std::memory_order_acq_rel))
        {
            write_signal_.expires_at(std::chrono::steady_clock::time_point::max());
            boost::system::error_code wait_ec;
            co_await write_signal_.async_wait(
                net::redirect_error(trace::use_prefix_awaitable, wait_ec));
            // wait_ec 无论成功还是 aborted 都无所谓，循环再次尝试 CAS
        }
        co_return;
    }


    void restls_transport::release_write_lock() noexcept
    {
        write_busy_.store(false, std::memory_order_release);
        // 唤醒所有等待者（cancel 让 async_wait 返回 aborted，等待者循环重试 CAS）
        write_signal_.cancel();
        write_signal_.expires_at(std::chrono::steady_clock::time_point::max());
    }


    auto restls_transport::write_restls_frame(std::span<const std::byte> data, std::error_code &ec, bool /*force_noop*/)
        -> net::awaitable<std::size_t>
    {
        ec.clear();

        // 互斥：保证 read 路径（send_random_response）和 write 路径（send_loop）
        // 不会同时进入 write_restls_frame，避免 counter 与 TCP 发送顺序不一致。
        co_await acquire_write_lock();

        // RAII 释放：协程帧销毁时（co_return 后）析构，自动 release
        struct write_lock_guard
        {
            restls_transport *self;
            explicit write_lock_guard(restls_transport *s) noexcept : self(s) {}
            ~write_lock_guard() noexcept { if (self) self->release_write_lock(); }
            write_lock_guard(const write_lock_guard &) = delete;
            auto operator=(const write_lock_guard &) = delete;
        };
        write_lock_guard guard{this};

        // 循环分片：每次写入 alloc.data_len 字节（受 max_plaintext - auth_hdrlen 限制），
        // 直到 data 全部写完。对应 mihomo conn.go:1481 for len(data) > 0 || fakeResponse。
        // 单帧过大（如 16401B SS2022 chunk）会被分成多个 restls record，
        // 否则 client 触发 alertRecordOverflow → 发 close_notify → 连接被关。
        // 空 data（magic response）：循环只执行一次，写单帧 padding。
        std::size_t total_written = 0;
        auto remaining = data;
        bool first_loop = true;

        while (first_loop || !remaining.empty())
        {
            first_loop = false;
            auto alloc = script_.allocate(write_counter_, remaining.size());

            // 本次帧的 data 长度：受 alloc.data_len 限制
            const std::size_t data_len =
                remaining.empty() ? std::size_t{0}
                                  : std::min<std::size_t>(remaining.size(),
                                                       static_cast<std::size_t>(
                                                           std::max<std::int16_t>(0, alloc.data_len)));
            if (!remaining.empty() && data_len == 0)
            {
                // 防御：还有剩余 data 但 script 没分配任何容量
                ec = std::make_error_code(std::errc::message_size);
                break;
            }

            // 空 data 帧（random-response）：必须使用 script 算的 padding（19-118B），
            // 否则 client 认为协议异常，立即发 TLS alert 关闭连接，
            // 导致后续 SS2022 handshake 读不到数据 → decrypt variable header failed
            // 非空 data 帧：padding=0（client 不验证 padding 长度，且 padding>0 实测会触发 alert）
            std::size_t padding_len;
            if (data_len == 0)
            {
                padding_len = static_cast<std::size_t>(
                    std::max<std::int16_t>(0, alloc.padding_len));
            }
            else
            {
                padding_len = (alloc.data_len > static_cast<std::int16_t>(data_len))
                                  ? static_cast<std::size_t>(alloc.data_len) - data_len
                                  : 0;
            }
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

            if (data_len > 0)
            {
                std::memcpy(payload + appdata_offset,
                            reinterpret_cast<const std::uint8_t *>(remaining.data()), data_len);
            }

            if (padding_len > 0)
                std::memset(payload + appdata_offset + data_len, 0, padding_len);

            // 计算 mask（基于明文 data 区域）
            const auto plaintext_sample_len = std::min<std::size_t>(32, payload_size - appdata_offset);
            auto mask = compute_mask(mask_input{
                .secret = std::span<const std::uint8_t, 32>(secret_),
                .server_random = std::span<const std::uint8_t, 32>(server_random_),
                .direction = flow_direction::to_client,
                .counter = to_client_counter_,
                .plaintext_sample = std::span<const std::uint8_t>(payload + appdata_offset,
                    plaintext_sample_len),
            });

            // DEBUG: dump mask 计算输入（受环境变量 PRISM_RESTLS_DEBUG 控制）
            if (restls_debug_enabled())
            {
                const auto sample_hex = to_hex_string(payload + appdata_offset, plaintext_sample_len);
                const auto mask_hex = to_hex_string(mask.data(), mask.size());
                trace::info<flt::conn | flt::protocol>(
                    "[DBG] s2c mask: ctr={} sample_len={} sample_hex={} mask={}",
                    to_client_counter_, plaintext_sample_len,
                    sample_hex, mask_hex);
            }

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

            // DEBUG: dump 完整 frame bytes + authMac 输入
            if (restls_debug_enabled())
            {
                const auto frame_hex = to_hex_string(record_data, record.size());
                const auto pload_hex = to_hex_string(payload + appdata_maclen, payload_size - appdata_maclen);
                trace::info<flt::conn | flt::protocol>(
                    "[DBG] s2c frame: ctr={} data_len={} padding={} payload_size={} "
                    "pload_after_mac={} frame_hex={}",
                    to_client_counter_, data_len, padding_len, payload_size,
                    pload_hex, frame_hex);
            }

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
                break;
            }
            (void)written;

            ++to_client_counter_;
            ++write_counter_;

            if (alloc.write_blocking)
                write_pending_ = true;

            trace::debug<flt::conn | flt::protocol>(
                "restls write_frame: data_len={}, payload={}, to_cli_ctr={}, blocking={}, transport={}",
                data_len, payload_size, to_client_counter_, alloc.write_blocking,
                reinterpret_cast<void*>(this));

            total_written += data_len;
            if (data_len > 0)
                remaining = remaining.subspan(data_len);

            // blocking 帧（Prism 主动发的 ActResponse）：script 要求等客户端回 magic，
            // 此时剩余 data 应当由后续 write_restls_frame 调用再次触发（write_pending_ 已设）。
            if (alloc.write_blocking)
                break;
        }

        if (ec)
            co_return total_written;

        co_return total_written == 0 && data.empty()
                   ? std::size_t{0}  // 空 data 调用（send_random_response）也认为成功
                   : total_written;
    }


    auto restls_transport::send_random_response(std::uint8_t count, std::error_code &ec)
        -> net::awaitable<void>
    {
        ec.clear();
        // 协议要求：random-response 帧的 data 必须为空，仅 padding。
        // 客户端收到 dataLen=0 时会在 readRecordOrCCS 中 retryReadRecord 丢弃该帧，
        // 不污染上层 SS2022 流。若写 magic 字符串作为 data，会被 SS2022 当作
        // salt/header 读取，导致 AEAD message authentication failed。
        // 参考 restls-client-go conn.go:1461 fakeResponse 把 dataNew 设为空 []byte{}。
        for (std::uint8_t i = 0; i < count; ++i)
        {
            co_await write_restls_frame({}, ec);
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
