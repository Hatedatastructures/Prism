/**
 * @file conn.cpp
 * @brief VMess 协议中继器实�? */

#include <prism/protocol/vmess/handler/conn.hpp>

#include <prism/foundation/fault/handling.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/protocol/common/read.hpp>
#include <prism/protocol/common/udprelay.hpp>
#include <prism/protocol/vmess/codec/auth.hpp>
#include <prism/protocol/vmess/codec/kdf.hpp>
#include <prism/user/stats/traffic.hpp>
#include <prism/diagnose/diagnose.hpp>

#include <openssl/evp.h>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstring>

using namespace boost::asio::experimental::awaitable_operators;

namespace psm::protocol::vmess
{

    using protocol::common::read_min;
    using protocol::common::read_remaining;

    namespace
    {
        /// 当前 Unix 时间戳（秒）
        [[nodiscard]] auto now_seconds() -> std::int64_t
        {
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }
    } // namespace

    conn::conn(shared_transmission next_layer, const config &cfg, std::vector<user_key> keys)
        : next_layer_(std::move(next_layer))
        , config_(cfg)
        , keys_(std::move(keys))
    {
    }

    auto conn::executor() const -> executor_type
    {
        return next_layer_->executor();
    }

    auto conn::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (!reader_)
        {
            ec = std::make_error_code(std::errc::not_connected);
            co_return 0;
        }
        auto n = co_await reader_->read_chunk(buffer, ec);        if (ec)
        {
            co_return 0;
        }
        if (n == 0)
        {
            ec = psm::fault::make_error_code(psm::fault::code::eof);
            co_return 0;
        }
        co_return n;
    }

    auto conn::async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (!writer_)
        {
            ec = std::make_error_code(std::errc::not_connected);
            co_return 0;
        }
        co_return co_await writer_->write_chunk(buffer, ec);
    }

    void conn::close()
    {
        if (next_layer_)
            next_layer_->close();
    }

    void conn::cancel()
    {
        if (next_layer_)
            next_layer_->cancel();
    }

    auto conn::underlying() noexcept -> psm::transport::transmission &
    {
        return *next_layer_;
    }

    auto conn::underlying() const noexcept -> const psm::transport::transmission &
    {
        return *next_layer_;
    }

    auto conn::release() -> shared_transmission
    {
        return std::move(next_layer_);
    }

    auto conn::handshake() const
        -> net::awaitable<std::pair<fault::code, request>>
    {
        request req;
        if (next_layer_ == nullptr)
        {
            co_return std::pair{fault::code::io_error, req};
        }

        // 握手超时�?0 秒）：防恶意客户端连接后不发数据挂起
        net::steady_timer deadline(next_layer_->executor(), std::chrono::seconds(30));
        auto on_deadline = [this](const boost::system::error_code &ec)
        {
            if (!ec && this->next_layer_)
                this->next_layer_->cancel();
        };
        deadline.async_wait(std::move(on_deadline));

        // 精确分段读取认证头（不超读，避免吞掉数据块）�?        // [authID 16][len �?18][connNonce 8][载荷 headerLen+16]
        std::array<std::byte, 16> auth_id{};
        std::array<std::byte, 18> len_block{};
        std::array<std::byte, 8> conn_nonce_raw{};
        {
            std::error_code re_ec;
            co_await transport::async_read(*next_layer_, auth_id, re_ec);
            if (fault::failed(re_ec))
            {
                deadline.cancel();
                co_return std::pair{fault::to_code(re_ec), req};
            }
            co_await transport::async_read(*next_layer_, len_block, re_ec);
            if (fault::failed(re_ec))
            {
                deadline.cancel();
                co_return std::pair{fault::to_code(re_ec), req};
            }
            co_await transport::async_read(*next_layer_, conn_nonce_raw, re_ec);
            if (fault::failed(re_ec))
            {
                deadline.cancel();
                co_return std::pair{fault::to_code(re_ec), req};
            }
        }
        const auto auth_span = std::span<const std::uint8_t, 16>(
            reinterpret_cast<const std::uint8_t *>(auth_id.data()), 16);
        const auto conn_nonce = std::span<const std::uint8_t, 8>(
            reinterpret_cast<const std::uint8_t *>(conn_nonce_raw.data()), 8);

        // 枚举用户解密认证头（CRC + 时间窗）
        const auto now = now_seconds();
        bool user_found = false;
        std::array<std::uint8_t, 16> cmd_key{};
        for (const auto &key : keys_)
        {
            const auto auth = codec::open_auth_header(
                std::span<const std::uint8_t, 16>(key.cmd_key.data(), 16), auth_span);
            if (!auth.valid)
                continue;
            const auto diff = auth.timestamp > now ? auth.timestamp - now : now - auth.timestamp;
            if (diff > time_tolerance)
                continue;
            cmd_key = key.cmd_key;
            user_found = true;
            break;
        }
        if (!user_found)
        {
            deadline.cancel();
            co_return std::pair{fault::code::auth_failed, req};
        }

        // �ⳤ�ȿ飬�����Ⱦ�ȷ��ȡ�غɿ�
        std::size_t header_len = 0;
        const auto len_ec = codec::open_len_block(
            std::span<const std::uint8_t, 16>(cmd_key.data(), 16), auth_span,
            std::span<const std::uint8_t, 18>(reinterpret_cast<const std::uint8_t *>(len_block.data()), 18),
            conn_nonce, header_len);
        if (fault::failed(len_ec))
        {
            deadline.cancel();
            co_return std::pair{len_ec, req};
        }
        memory::vector<std::byte> payload_block(header_len + 16);
        {
            std::error_code pe_ec;
            co_await transport::async_read(*next_layer_, payload_block, pe_ec);
            if (fault::failed(pe_ec))
            {
                deadline.cancel();
                co_return std::pair{fault::to_code(pe_ec), req};
            }
        }

        // decrypt request header
        codec::request_header header;
        const auto header_ec = codec::open_payload(
            std::span<const std::uint8_t, 16>(cmd_key.data(), 16), auth_span, conn_nonce,
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(payload_block.data()),
                                          payload_block.size()),
            header);
        if (fault::failed(header_ec))
        {
            deadline.cancel();
            co_return std::pair{header_ec, req};
        }

        // 命令校验
        const auto command_byte = header.command;
        const bool is_udp = command_byte == static_cast<std::uint8_t>(command::udp);
        const bool is_mux = command_byte == static_cast<std::uint8_t>(command::mux);
        if (!is_udp && !is_mux &&
            command_byte != static_cast<std::uint8_t>(command::tcp))
        {
            deadline.cancel();
            co_return std::pair{fault::code::unsupported_command, req};
        }
        if (is_udp && header.option == 0)
        {
            deadline.cancel();
            co_return std::pair{fault::code::bad_message, req};
        }
        if (is_mux && !config_.enable_mux)
        {
            deadline.cancel();
            co_return std::pair{fault::code::forbidden, req};
        }

        // write response header (AEAD two-part GCM)
        std::array<std::byte, 38> resp{};
        const auto resp_ec = codec::build_response(
            std::span<const std::uint8_t, 16>(header.request_key.data(), 16),
            std::span<const std::uint8_t, 16>(header.request_nonce.data(), 16),
            header.response_header, header.option, false,
            std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(resp.data()), resp.size()));
        if (fault::failed(resp_ec))
        {
            deadline.cancel();
            co_return std::pair{resp_ec, req};
        }
        std::error_code w_ec;
        co_await next_layer_->async_write_some(resp, w_ec);
        if (w_ec)
        {
            deadline.cancel();
            co_return std::pair{fault::to_code(w_ec), req};
        }

        // 响应侧密钥：SHA256(requestKey/requestNonce)[:16]
        std::array<std::uint8_t, 16> resp_key{};
        std::array<std::uint8_t, 16> resp_nonce{};
        std::array<std::uint8_t, 32> key_hash{};
        std::array<std::uint8_t, 32> nonce_hash{};
        EVP_Digest(header.request_key.data(), 16, key_hash.data(), nullptr, EVP_sha256(), nullptr);
        EVP_Digest(header.request_nonce.data(), 16, nonce_hash.data(), nullptr, EVP_sha256(), nullptr);
        std::memcpy(resp_key.data(), key_hash.data(), 16);
        std::memcpy(resp_nonce.data(), nonce_hash.data(), 16);

        reader_ = std::make_unique<codec::read_stream>(codec::stream_params{
            .transport = next_layer_.get(),
            .key = header.request_key,
            .nonce = header.request_nonce,
            .option = header.option,
            .security = header.security});
        writer_ = std::make_unique<codec::write_stream>(codec::stream_params{
            .transport = next_layer_.get(),
            .key = resp_key,
            .nonce = resp_nonce,
            .option = header.option,
            .security = header.security});

        deadline.cancel();

        // 填充结果
        header_ = header;
        req.command = command_byte;
        req.destination = header.destination;
        req.port = header.port;
        co_return std::pair{fault::code::success, req};
    }

    auto conn::async_associate(route_callback route_cb) const
        -> net::awaitable<fault::code>
    {
        using namespace boost::asio::experimental::awaitable_operators;
        if (!config_.enable_udp)
        {
            co_return fault::code::not_supported;
        }
        if (!next_layer_ || !reader_ || !writer_)
        {
            co_return fault::code::io_error;
        }

        // resolve fixed target (address from request header)
        auto host = psm::protocol::common::addr_to_str(header_.destination);
        char port_buf[8];
        const auto [pe, pec] = std::to_chars(
            port_buf, port_buf + sizeof(port_buf), static_cast<std::uint32_t>(header_.port));
        auto [route_ec, target_ep] = co_await route_cb(
            std::string_view(host), std::string_view(port_buf, std::distance(port_buf, pe)));
        if (fault::failed(route_ec))
        {
            co_return route_ec;
        }

        net::steady_timer idle_timer(next_layer_->executor());
        protocol::common::udp_buffers buf(config_.max_dgram);
        net::ip::udp::socket udp_socket(next_layer_->executor());
        std::uint64_t uplink_bytes = 0;
        std::uint64_t downlink_bytes = 0;

        while (true)
        {
            idle_timer.expires_after(std::chrono::seconds(config_.idle_timeout));

            auto do_read = [&]()
                -> net::awaitable<std::size_t>
            {
                std::error_code ec;
                const auto n = co_await reader_->read_chunk(buf.recv, ec);
                if (ec || n == 0)
                {
                    co_return 0;
                }
                co_return n;
            };

            const auto read_result = co_await (do_read() || idle_timer.async_wait(net::use_awaitable));
            if (read_result.index() == 1)
            {
                // 空闲超时
                if (traffic_)
                    traffic_->flush_traffic(proto_, uplink_bytes, downlink_bytes);
                co_return fault::code::success;
            }

            const auto n = std::get<0>(read_result);
            idle_timer.cancel();
            if (n == 0)
            {
                if (traffic_)
                    traffic_->flush_traffic(proto_, uplink_bytes, downlink_bytes);
                co_return fault::code::success;
            }

            auto [relay_ec, resp_n, sender_ep] = co_await protocol::common::relay_packet(
                protocol::common::relay_opts{udp_socket, target_ep,
                                             std::span<const std::byte>(buf.recv.data(), n), buf});
            if (fault::failed(relay_ec))
            {
                continue;
            }
            (void)sender_ep;
            uplink_bytes += n;

            // echo packet: wrap as data chunk
            std::error_code w_ec;
            co_await writer_->write_chunk(std::span<const std::byte>(buf.response.data(), resp_n), w_ec);
            if (w_ec)
            {
                if (traffic_)
                    traffic_->flush_traffic(proto_, uplink_bytes, downlink_bytes);
                co_return fault::code::success;
            }
            downlink_bytes += resp_n;
        }
    }

} // namespace psm::protocol::vmess

