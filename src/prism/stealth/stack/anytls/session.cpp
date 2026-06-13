#include <prism/stealth/stack/anytls/mux/session.hpp>

#include <prism/core/fault/handling.hpp>
#include <prism/stealth/stack/anytls/mux/transport.hpp>
#include <prism/trace/trace.hpp>

#include <cstring>

using namespace psm::trace;

namespace psm::stealth::anytls
{

    anytls_session::anytls_session(
        transport::shared_transmission tls_transport,
        std::shared_ptr<padding_factory> padding,
        stream_callback on_new_stream)
        : transport_(std::move(tls_transport))
        , on_new_stream_(std::move(on_new_stream))
        , write_strand_(transport_->get_executor())
        , padding_(std::move(padding))
        , init_waiter_(transport_->get_executor())
    {
        // 定时器立即过期，用于等待第一个 stream
        init_waiter_.expires_after(std::chrono::hours(24));
    }

    void anytls_session::start()
    {
        auto self = shared_from_this();
        auto recv_task = [self]() -> net::awaitable<void>
        {
            co_await self->recv_loop();
        };
        net::co_spawn(transport_->get_executor(), std::move(recv_task), net::detached);
    }

    auto anytls_session::wait_first_stream()
        -> net::awaitable<std::pair<fault::code,
            std::tuple<std::uint32_t, memory::vector<std::uint8_t>>>>
    {
        if (init_resolved_)
        {
            auto result = std::pair{init_error_,
                std::tuple{init_id_, std::move(init_preread_)}};
            co_return result;
        }

        // 等待 recv_loop 通知
        boost::system::error_code ec;
        co_await init_waiter_.async_wait(net::redirect_error(trace::use_prefix_awaitable, ec));

        auto result2 = std::pair{init_error_,
            std::tuple{init_id_, std::move(init_preread_)}};
        co_return result2;
    }

    auto anytls_session::recv_loop() -> net::awaitable<void>
    {
        try
        {
            std::array<std::byte, 7> header_buf{};

            while (!closed_)
            {
                if (!co_await read_exact(header_buf))
                {
                    trace::debug<flt::conn | flt::protocol>("connection closed during header read");
                    break;
                }

                // 安全：将 byte 缓冲区转为 uint8_t span 用于帧头解析，内存布局相同
                auto header = frame_header::parse(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(header_buf.data()),
                        frame_header_size));

                if (!header)
                {
                    trace::warn<flt::conn | flt::protocol>("invalid frame header");
                    break;
                }

                memory::vector<std::uint8_t> payload(header->length);
                if (header->length > 0)
                {
                    // 安全：将 uint8_t vector 转为可变 byte span 用于异步读取
                    if (!co_await read_exact(
                        std::span<std::byte>(
                            reinterpret_cast<std::byte *>(payload.data()),
                            payload.size())))
                    {
                        trace::debug<flt::conn | flt::protocol>("connection closed during payload read");
                        break;
                    }
                }

                if (padding_ && padding_->enabled())
                {
                    std::error_code pad_ec;
                    co_await send_waste_frame(pkt_counter_, pad_ec);
                    if (pad_ec)
                    {
                        trace::warn<flt::conn | flt::protocol>("padding frame failed: {}", pad_ec.message());
                    }
                    ++pkt_counter_;
                }

                co_await dispatch_frame(*header, std::move(payload));
            }
        }
        catch (...)
        {
            trace::error<flt::conn | flt::protocol>("recv_loop exception, closing session");
        }

        for (auto &[id, ch] : streams_)
        {
            ch->try_send(
                boost::system::errc::make_error_code(boost::system::errc::connection_reset),
                memory::vector<std::uint8_t>{});
        }
        streams_.clear();

        if (!init_resolved_)
        {
            init_error_ = fault::code::eof;
            init_resolved_ = true;
            init_waiter_.cancel();
        }

        closed_ = true;
        if (transport_)
            transport_->close();

        trace::debug<flt::conn | flt::protocol>("recv_loop ended");
    }

    auto anytls_session::dispatch_frame(const frame_header &hdr, memory::vector<std::uint8_t> payload)
        -> net::awaitable<void>
    {
        switch (hdr.cmd)
        {
        case command::settings:
            co_await on_settings(std::move(payload));
            break;
        case command::syn:
            co_await on_syn(hdr.stream_id);
            break;
        case command::psh:
            co_await on_psh(hdr.stream_id, std::move(payload));
            break;
        case command::fin:
            co_await on_fin(hdr.stream_id);
            break;
        case command::alert:
        {
            auto stream_id = hdr.stream_id;
            auto it = streams_.find(stream_id);
            if (it != streams_.end())
            {
                it->second->try_send(
                    boost::system::errc::make_error_code(boost::system::errc::connection_reset),
                    memory::vector<std::uint8_t>{});
                streams_.erase(it);
            }
            trace::debug<flt::conn | flt::protocol>("ALERT stream_id={}", stream_id);
            break;
        }
        case command::heart_req:
        {
            std::error_code heart_ec;
            co_await write_frame(frame_input{command::heart_resp, 0, {}, heart_ec});
            if (heart_ec)
            {
                trace::warn<flt::conn | flt::protocol>("heartbeat response failed: {}", heart_ec.message());
            }
            else
            {
                trace::debug<flt::conn | flt::protocol>("heartbeat response sent");
            }
            break;
        }
        case command::waste:
            break;
        default:
            trace::debug<flt::conn | flt::protocol>("unhandled command: {}", static_cast<int>(hdr.cmd));
            break;
        }
    }

    auto anytls_session::on_settings(memory::vector<std::uint8_t> payload) -> net::awaitable<void>
    {
        received_settings_ = true;

        // 安全：将 uint8_t payload 转为 string_view 用于文本协议解析
        auto text = std::string_view(
            reinterpret_cast<const char *>(payload.data()), payload.size());

        // 查找 "v=N"
        auto v_pos = text.find("v=");
        if (v_pos != std::string_view::npos)
        {
            auto v_end = text.find('\n', v_pos);
            std::size_t v_len = std::string_view::npos;
            if (v_end != std::string_view::npos)
                v_len = v_end - v_pos - 2;
            auto v_str = text.substr(v_pos + 2, v_len);
            peer_version_ = static_cast<std::uint32_t>(std::atoi(std::string(v_str).c_str()));
        }

        // mihomo: 解析 padding-md5，比对后可能发送 update_padding
        if (peer_version_ >= 2 && padding_ && padding_->enabled())
        {
            auto md5_pos = text.find("padding-md5=");
            if (md5_pos != std::string_view::npos)
            {
                auto md5_start = md5_pos + 12;
                auto md5_end = text.find('\n', md5_start);
                std::size_t md5_len = std::string_view::npos;
                if (md5_end != std::string_view::npos)
                    md5_len = md5_end - md5_start;
                auto client_md5 = text.substr(md5_start, md5_len);

                if (client_md5 != std::string_view(padding_->md5.data(), padding_->md5.size()))
                {
                    trace::debug<flt::conn | flt::protocol>("client padding-md5 mismatch, sending update");
                    std::error_code up_ec;
                    co_await write_frame(frame_input{command::update_padding, 0,
                        // 安全：将字符串数据转为 byte span 用于帧传输
                        std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(padding_->raw_scheme_.data()),
                            padding_->raw_scheme_.size()), up_ec});
                }
            }
        }

        // 如果 v>=2，发送 cmdServerSettings
        if (peer_version_ >= 2)
        {
            auto settings_text = std::string("v=2\nserver=prism\n");
            std::error_code wr_ec;
            co_await write_frame(frame_input{command::server_settings, 0,
                // 安全：将字符串数据转为 byte span 用于帧传输
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(settings_text.data()),
                    settings_text.size()), wr_ec});
            if (wr_ec)
            {
                trace::warn<flt::conn | flt::protocol>("failed to send server settings: {}", wr_ec.message());
            }
        }

        trace::debug<flt::conn | flt::protocol>("Settings received, version={}", peer_version_);
    }

    auto anytls_session::on_syn(std::uint32_t stream_id) -> net::awaitable<void>
    {
        // mihomo: 服务端在收到 Settings 之前忽略 SYN
        if (!received_settings_)
        {
            trace::warn<flt::conn | flt::protocol>("SYN before Settings, ignoring");
            co_return;
        }

        if (stream_id == 0)
        {
            trace::warn<flt::conn | flt::protocol>("SYN with stream_id=0");
            co_return;
        }

        // 创建 channel
        auto channel = std::make_shared<channel_type>(
            transport_->get_executor(), 64);
        streams_[stream_id] = channel;

        // mihomo: SYNACK 在 stream 处理完 SOCKS 地址后发送（HandshakeSuccess）
        // 这里先不发送 SYNACK，等 scheme.cpp 的 on_new_stream 处理完再发

        // 记录第一个 stream 的 ID
        if (init_id_ == 0)
        {
            init_id_ = stream_id;
        }
        else
        {
            // 后续 stream：记录等待第一个 PSH（携带 SOCKS 地址）
            pending_syns_.insert(stream_id);
        }

        trace::debug<flt::conn | flt::protocol>("SYN stream_id={}", stream_id);
    }

    auto anytls_session::on_psh(std::uint32_t stream_id, memory::vector<std::uint8_t> payload) -> net::awaitable<void>
    {
        // 第一个 stream 的第一个 PSH：保存 preread 数据用于解析 SOCKS 目标
        // 不发送到 channel——数据由 handle_first_stream() 消费，
        // channel 只接收后续 PSH 数据，避免 SOCKS 地址被 relay 到目标服务器
        if (!init_resolved_ && stream_id == init_id_ && stream_id != 0)
        {
            init_preread_ = std::move(payload);
            init_resolved_ = true;

            init_waiter_.cancel();
            co_return;
        }

        // 后续 stream 的 PSH
        if (init_id_ != 0 && stream_id != init_id_)
        {
            auto it = streams_.find(stream_id);
            if (it != streams_.end())
            {
                // 检查是否是后续 stream 的第一个 PSH（携带 SOCKS 地址）
                auto syn_it = pending_syns_.find(stream_id);
                if (syn_it != pending_syns_.end())
                {
                    pending_syns_.erase(syn_it);

                    // 触发 on_new_stream（携带 SOCKS 地址数据）
                    if (on_new_stream_)
                    {
                        auto stream_trans = std::make_shared<anytls_stream_transport>(
                            shared_from_this(), stream_id, it->second);
                        on_new_stream_(stream_id,
                            std::move(stream_trans),
                            std::move(payload));

                        // 发送 SYNACK（v2+）
                        if (peer_version_ >= 2)
                        {
                            std::error_code synack_ec;
                            co_await write_synack(stream_id, synack_ec);
                        }
                    }
                    co_return;
                }

                it->second->try_send(boost::system::error_code{}, std::move(payload));
                co_return;
            }

            trace::warn<flt::conn | flt::protocol>("PSH for unknown stream_id={}", stream_id);
            co_return;
        }

        // 第一个 stream 的后续 PSH
        auto it = streams_.find(stream_id);
        if (it != streams_.end())
        {
            it->second->try_send(boost::system::error_code{}, std::move(payload));
        }
        else
        {
            trace::warn<flt::conn | flt::protocol>("PSH for unknown stream_id={}", stream_id);
        }
    }

    auto anytls_session::on_fin(std::uint32_t stream_id) -> net::awaitable<void>
    {
        auto it = streams_.find(stream_id);
        if (it != streams_.end())
        {
            it->second->try_send(
                boost::system::errc::make_error_code(boost::system::errc::connection_reset),
                memory::vector<std::uint8_t>{});
            streams_.erase(it);
        }
        trace::debug<flt::conn | flt::protocol>("FIN stream_id={}", stream_id);
        co_return;
    }

    auto anytls_session::read_exact(std::span<std::byte> buf) -> net::awaitable<bool>
    {
        std::size_t total = 0;
        while (total < buf.size())
        {
            std::error_code ec;
            auto n = co_await transport_->async_read_some(
                buf.subspan(total), ec);
            if (ec || n == 0)
            {
                co_return false;
            }
            total += n;
        }
        co_return true;
    }

    auto anytls_session::write_frame(frame_input input) -> net::awaitable<void>
    {
        // 通过 write_strand_ 序列化写入，防止多 stream 并发写入帧交错
        co_await net::dispatch(write_strand_, trace::use_prefix_awaitable);

        frame_header hdr;
        hdr.cmd = input.cmd;
        hdr.stream_id = input.stream_id;
        hdr.length = static_cast<std::uint16_t>(input.data.size());

        auto serialized = hdr.serialize();

        // 写入 header
        // 安全：将序列化帧头 vector 转为 byte span 用于网络传输
        co_await transport::async_write(*transport_,
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(serialized.data()),
                serialized.size()),
            input.ec);

        if (input.ec)
        {
            trace::warn<flt::conn | flt::protocol>("write_frame header failed: {}", input.ec.message());
            co_return;
        }

        // 写入 payload
        if (!input.data.empty())
        {
            co_await transport::async_write(*transport_, input.data, input.ec);
            if (input.ec)
            {
                trace::warn<flt::conn | flt::protocol>("write_frame payload failed: {}", input.ec.message());
            }
        }

    }

    auto anytls_session::send_waste_frame(std::uint32_t pkt_num, std::error_code &ec) -> net::awaitable<void>
    {
        if (!padding_ || !padding_->enabled())
        {
            co_return;
        }

        auto sizes = padding_->generate_sizes(pkt_num);
        for (auto size : sizes)
        {
            if (size == padding_factory::checkmark)
            {
                continue;
            }

            memory::vector<std::uint8_t> waste_data(size, 0);
            co_await write_frame(frame_input{command::waste, 0,
                // 安全：将 uint8_t vector 转为 byte span 用于 waste 帧传输
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(waste_data.data()),
                    waste_data.size()), ec});
            if (ec)
            {
                co_return;
            }
        }
    }

    auto anytls_session::write_psh(std::uint32_t stream_id, std::span<const std::byte> data,
                                    std::error_code &ec) -> net::awaitable<std::size_t>
    {
        co_await write_frame(frame_input{command::psh, stream_id, data, ec});
        if (ec)
        {
            co_return 0;
        }
        co_return data.size();
    }

    auto anytls_session::write_fin(std::uint32_t stream_id, std::error_code &ec) -> net::awaitable<void>
    {
        co_await write_frame(frame_input{command::fin, stream_id, {}, ec});
    }

    auto anytls_session::write_synack(std::uint32_t stream_id, std::error_code &ec) -> net::awaitable<void>
    {
        co_await write_frame(frame_input{command::synack, stream_id, {}, ec});
    }

    [[nodiscard]] auto anytls_session::get_stream_channel(std::uint32_t stream_id) const
        -> std::shared_ptr<channel_type>
    {
        auto it = streams_.find(stream_id);
        if (it != streams_.end())
        {
            return it->second;
        }
        return nullptr;
    }

    void anytls_session::close()
    {
        closed_ = true;
        if (transport_)
        {
            transport_->close();
        }

        // 通知 wait_first_stream（如果还在等待）
        if (!init_resolved_)
        {
            init_error_ = fault::code::eof;
            init_resolved_ = true;
            init_waiter_.cancel();
        }
    }
} // namespace psm::stealth::anytls
