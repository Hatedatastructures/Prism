/**
 * @file transport.hpp
 * @brief AnyTLS stream 传输层
 * @details 将单个 AnyTLS stream 的数据读写适配为 transmission 接口。
 * 读取方向从 anytls_session 的 concurrent_channel 获取数据，
 * 写入方向通过 anytls_session::write_psh 发送数据。
 */
#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include <prism/transport/transmission.hpp>
#include <prism/stealth/anytls/mux/session.hpp>

namespace psm::stealth::anytls
{
    namespace net = boost::asio;

    /**
     * @class anytls_stream_transport
     * @brief AnyTLS stream 传输层
     * @details 适配单个 AnyTLS stream 为 transmission 接口。
     */
    class anytls_stream_transport final : public transport::transmission
    {
    public:
        using channel_type = anytls_session::channel_type;

        explicit anytls_stream_transport(
            std::shared_ptr<anytls_session> session,
            std::uint32_t stream_id,
            std::shared_ptr<channel_type> channel)
            : session_(std::move(session))
            , stream_id_(stream_id)
            , channel_(std::move(channel))
        {
        }

        [[nodiscard]] auto transport_type() const noexcept
            -> type override
        {
            return type::tcp;
        }

        [[nodiscard]] transmission *next_layer() noexcept override { return nullptr; }
        [[nodiscard]] const transmission *next_layer() const noexcept override { return nullptr; }

        [[nodiscard]] executor_type executor() const override
        {
            return channel_->get_executor();
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            // 先消费 pending 缓冲区
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
                ec.clear();
                co_return n;
            }

            if (!channel_)
            {
                ec = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }

            auto [recv_ec, chunk] = co_await channel_->async_receive(
                net::as_tuple(net::use_awaitable));

            if (recv_ec)
            {
                ec = recv_ec;
                co_return 0;
            }

            const auto n = std::min(chunk.size(), buffer.size());
            std::memcpy(buffer.data(), chunk.data(), n);

            if (chunk.size() > n)
            {
                pending_buffer_.assign(chunk.begin() + n, chunk.end());
                pending_offset_ = 0;
            }

            ec.clear();
            co_return n;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            return session_->write_psh(stream_id_, buffer, ec);
        }

        void close() override
        {
            if (channel_)
            {
                channel_->try_send(
                    boost::system::errc::make_error_code(boost::system::errc::connection_reset),
                    std::vector<std::uint8_t>{});
                channel_.reset();
            }
            // 发送 FIN
            auto self = session_;
            auto sid = stream_id_;
            net::co_spawn(executor(),
                [self, sid]() -> net::awaitable<void>
                {
                    std::error_code ec;
                    co_await self->write_fin(sid, ec);
                },
                net::detached);
        }

        void cancel() override { close(); }

    private:
        std::shared_ptr<anytls_session> session_;
        std::uint32_t stream_id_;
        std::shared_ptr<channel_type> channel_;
        std::vector<std::uint8_t> pending_buffer_;
        std::size_t pending_offset_{0};
    };
} // namespace psm::stealth::anytls
