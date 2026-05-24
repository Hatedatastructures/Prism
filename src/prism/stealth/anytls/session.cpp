/**
 * @file session.cpp
 * @brief AnyTLS 会话管理实现
 */

#include <prism/stealth/anytls/mux/session.hpp>
#include <prism/stealth/anytls/mux/stream_transport.hpp>
#include <prism/trace.hpp>
#include <prism/fault/handling.hpp>

#include <cstring>

namespace psm::stealth::anytls
{
    namespace
    {
        constexpr std::string_view tag = "[AnyTLS.Session]";
    } // namespace

    anytls_session::anytls_session(
        transport::shared_transmission tls_transport,
        std::shared_ptr<padding_factory> padding,
        stream_callback on_new_stream)
        : transport_(std::move(tls_transport))
        , on_new_stream_(std::move(on_new_stream))
        , write_strand_(transport_->get_executor())
        , padding_(std::move(padding))
        , first_stream_waiter_(transport_->get_executor())
    {
        // 定时器立即过期，用于等待第一个 stream
        first_stream_waiter_.expires_after(std::chrono::hours(24));
    }

    auto anytls_session::start() -> void
    {
        auto self = shared_from_this();
        net::co_spawn(transport_->get_executor(),
            [self]() -> net::awaitable<void>
            {
                co_await self->recv_loop();
            },
            net::detached);
    }

    auto anytls_session::wait_first_stream()
        -> net::awaitable<std::pair<fault::code,
            std::tuple<std::uint32_t, std::vector<std::uint8_t>>>>
    {
        if (first_stream_resolved_)
        {
            auto result = std::make_pair(first_stream_error_,
                std::make_tuple(first_stream_id_, std::move(first_stream_preread_)));
            co_return result;
        }

        // 等待 recv_loop 通知
        boost::system::error_code ec;
        co_await first_stream_waiter_.async_wait(net::redirect_error(net::use_awaitable, ec));

        auto result = std::make_pair(first_stream_error_,
            std::make_tuple(first_stream_id_, std::move(first_stream_preread_)));
        co_return result;
    }

    auto anytls_session::recv_loop() -> net::awaitable<void>
    {
        try
        {
        std::array<std::byte, 7> header_buf{};

        while (!closed_)
        {
            // 读取帧头
            if (!co_await read_exact(header_buf))
            {
                trace::debug("{} connection closed during header read", tag);
                break;
            }

            // safe: casting byte buffer to uint8_t span for frame header parsing, same memory layout
            auto header = frame_header::parse(
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(header_buf.data()),
                    frame_header_size));

            if (!header)
            {
                trace::warn("{} invalid frame header", tag);
                break;
            }

            // 读取 payload
            std::vector<std::uint8_t> payload(header->length);
            if (header->length > 0)
            {
                // safe: casting uint8_t vector to mutable byte span for async read
                if (!co_await read_exact(
                    std::span<std::byte>(
                        reinterpret_cast<std::byte *>(payload.data()),
                        payload.size())))
                {
                    trace::debug("{} connection closed during payload read", tag);
                    break;
                }
            }

            // 发送 padding 帧（如果配置了）
            if (padding_ && padding_->enabled())
            {
                std::error_code pad_ec;
                co_await send_waste_frame(pkt_counter_, pad_ec);
                if (pad_ec)
                {
                    trace::warn("{} padding frame failed: {}", tag, pad_ec.message());
                }
                ++pkt_counter_;
            }

            // 处理命令
            switch (header->cmd)
            {
            case command::settings:
            {
                received_settings_ = true;
                // 解析 version
                // safe: casting uint8_t payload to string_view for text protocol parsing
                auto text = std::string_view(
                    reinterpret_cast<const char *>(payload.data()), payload.size());
                // 查找 "v=N"
                auto v_pos = text.find("v=");
                if (v_pos != std::string_view::npos)
                {
                    auto v_end = text.find('\n', v_pos);
                    auto v_str = text.substr(v_pos + 2, v_end == std::string_view::npos ? v_end : v_end - v_pos - 2);
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
                        auto client_md5 = text.substr(md5_start,
                            md5_end == std::string_view::npos ? md5_end : md5_end - md5_start);

                        if (client_md5 != std::string_view(padding_->md5.data(), padding_->md5.size()))
                        {
                            trace::debug("{} client padding-md5 mismatch, sending update", tag);
                            std::error_code up_ec;
                            co_await write_frame(command::update_padding, 0,
                                // safe: casting string data to byte span for frame transmission
                                std::span<const std::byte>(
                                    reinterpret_cast<const std::byte *>(padding_->raw_scheme_.data()),
                                    padding_->raw_scheme_.size()), up_ec);
                        }
                    }
                }

                // 如果 v>=2，发送 cmdServerSettings
                if (peer_version_ >= 2)
                {
                    auto settings_text = std::string("v=2\nserver=prism\n");
                    std::error_code wr_ec;
                    co_await write_frame(command::server_settings, 0,
                        // safe: casting string data to byte span for frame transmission
                        std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(settings_text.data()),
                            settings_text.size()), wr_ec);
                    if (wr_ec)
                    {
                        trace::warn("{} failed to send server settings: {}", tag, wr_ec.message());
                    }
                }

                trace::debug("{} Settings received, version={}", tag, peer_version_);
                break;
            }

            case command::syn:
            {
                // mihomo: 服务端在收到 Settings 之前忽略 SYN
                if (!received_settings_)
                {
                    trace::warn("{} SYN before Settings, ignoring", tag);
                    break;
                }

                auto stream_id = header->stream_id;
                if (stream_id == 0)
                {
                    trace::warn("{} SYN with stream_id=0", tag);
                    break;
                }

                // 创建 channel
                auto channel = std::make_shared<channel_type>(
                    transport_->get_executor(), 64);
                streams_[stream_id] = channel;

                // mihomo: SYNACK 在 stream 处理完 SOCKS 地址后发送（HandshakeSuccess）
                // 这里先不发送 SYNACK，等 scheme.cpp 的 on_new_stream 处理完再发

                // 记录第一个 stream 的 ID
                if (first_stream_id_ == 0)
                {
                    first_stream_id_ = stream_id;
                }
                else
                {
                    // 后续 stream：记录等待第一个 PSH（携带 SOCKS 地址）
                    pending_syn_streams_.insert(stream_id);
                }

                trace::debug("{} SYN stream_id={}", tag, stream_id);
                break;
            }

            case command::psh:
            {
                auto stream_id = header->stream_id;

                // 第一个 stream 的第一个 PSH：保存 preread 数据
                if (!first_stream_resolved_ && stream_id == first_stream_id_ && stream_id != 0)
                {
                    first_stream_preread_ = payload;
                    first_stream_resolved_ = true;

                    // 同时发送到 channel 供 stream_transport 读取
                    auto it = streams_.find(stream_id);
                    if (it != streams_.end())
                    {
                        it->second->try_send(boost::system::error_code{}, std::move(payload));
                    }

                    first_stream_waiter_.cancel();
                }
                else if (first_stream_id_ != 0 && stream_id != first_stream_id_)
                {
                    // 后续 stream 的 PSH
                    auto it = streams_.find(stream_id);
                    if (it != streams_.end())
                    {
                        // 检查是否是后续 stream 的第一个 PSH（携带 SOCKS 地址）
                        auto syn_it = pending_syn_streams_.find(stream_id);
                        if (syn_it != pending_syn_streams_.end())
                        {
                            pending_syn_streams_.erase(syn_it);

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
                        }
                        else
                        {
                            it->second->try_send(boost::system::error_code{}, std::move(payload));
                        }
                    }
                    else
                    {
                        trace::warn("{} PSH for unknown stream_id={}", tag, stream_id);
                    }
                }
                else
                {
                    auto it = streams_.find(stream_id);
                    if (it != streams_.end())
                    {
                        it->second->try_send(boost::system::error_code{}, std::move(payload));
                    }
                    else
                    {
                        trace::warn("{} PSH for unknown stream_id={}", tag, stream_id);
                    }
                }

                break;
            }

            case command::fin:
            {
                auto stream_id = header->stream_id;
                auto it = streams_.find(stream_id);
                if (it != streams_.end())
                {
                    it->second->try_send(
                        boost::system::errc::make_error_code(boost::system::errc::connection_reset),
                        std::vector<std::uint8_t>{});
                    streams_.erase(it);
                }
                trace::debug("{} FIN stream_id={}", tag, stream_id);
                break;
            }

            case command::alert:
            {
                auto stream_id = header->stream_id;
                auto it = streams_.find(stream_id);
                if (it != streams_.end())
                {
                    it->second->try_send(
                        boost::system::errc::make_error_code(boost::system::errc::connection_reset),
                        std::vector<std::uint8_t>{});
                    streams_.erase(it);
                }
                trace::debug("{} ALERT stream_id={}", tag, stream_id);
                break;
            }

            case command::heart_req:
            {
                std::error_code heart_ec;
                co_await write_frame(command::heart_resp, 0, {}, heart_ec);
                if (heart_ec)
                {
                    trace::warn("{} heartbeat response failed: {}", tag, heart_ec.message());
                }
                else
                {
                    trace::debug("{} heartbeat response sent", tag);
                }
                break;
            }

            case command::waste:
                // 丢弃
                break;

            default:
                trace::debug("{} unhandled command: {}", tag, static_cast<int>(header->cmd));
                break;
            }
        }

        // 关闭所有 stream
        for (auto &[id, ch] : streams_)
        {
            ch->try_send(
                boost::system::errc::make_error_code(boost::system::errc::connection_reset),
                std::vector<std::uint8_t>{});
        }
        streams_.clear();

        // 如果第一个 stream 还没解析，通知错误
        if (!first_stream_resolved_)
        {
            first_stream_error_ = fault::code::eof;
            first_stream_resolved_ = true;
            first_stream_waiter_.cancel();
        }

        trace::debug("{} recv_loop ended", tag);
        }
        catch (...)
        {
            trace::error("[AnyTLS] recv_loop exception, closing session");
            close();
        }
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

    auto anytls_session::write_frame(command cmd, std::uint32_t stream_id,
                                      std::span<const std::byte> data, std::error_code &ec) -> net::awaitable<void>
    {
        frame_header hdr;
        hdr.cmd = cmd;
        hdr.stream_id = stream_id;
        hdr.length = static_cast<std::uint16_t>(data.size());

        auto serialized = hdr.serialize();

        // 写入 header
        // safe: casting serialized header vector to byte span for wire transmission
        co_await transport::async_write(*transport_,
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(serialized.data()),
                serialized.size()),
            ec);

        if (ec)
        {
            trace::warn("{} write_frame header failed: {}", tag, ec.message());
            co_return;
        }

        // 写入 payload
        if (!data.empty())
        {
            co_await transport::async_write(*transport_, data, ec);
            if (ec)
            {
                trace::warn("{} write_frame payload failed: {}", tag, ec.message());
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

            std::vector<std::uint8_t> waste_data(size, 0);
            co_await write_frame(command::waste, 0,
                // safe: casting uint8_t vector to byte span for waste frame transmission
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(waste_data.data()),
                    waste_data.size()), ec);
            if (ec)
            {
                co_return;
            }
        }
    }

    auto anytls_session::write_psh(std::uint32_t stream_id, std::span<const std::byte> data,
                                    std::error_code &ec) -> net::awaitable<std::size_t>
    {
        co_await write_frame(command::psh, stream_id, data, ec);
        if (ec)
        {
            co_return 0;
        }
        co_return data.size();
    }

    auto anytls_session::write_fin(std::uint32_t stream_id, std::error_code &ec) -> net::awaitable<void>
    {
        co_await write_frame(command::fin, stream_id, {}, ec);
    }

    auto anytls_session::write_synack(std::uint32_t stream_id, std::error_code &ec) -> net::awaitable<void>
    {
        co_await write_frame(command::synack, stream_id, {}, ec);
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

    auto anytls_session::close() -> void
    {
        closed_ = true;
        if (transport_)
        {
            transport_->close();
        }

        // 通知 wait_first_stream（如果还在等待）
        if (!first_stream_resolved_)
        {
            first_stream_error_ = fault::code::eof;
            first_stream_resolved_ = true;
            first_stream_waiter_.cancel();
        }
    }
} // namespace psm::stealth::anytls
