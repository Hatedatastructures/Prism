/**
 * @file transport.hpp
 * @brief AnyTLS stream 传输层
 * @details 将单个 AnyTLS stream 的数据读写适配为 transmission 接口。
 * 读取方向从 anytls_session 的 concurrent_channel 获取数据，
 * 写入方向通过 anytls_session::write_psh 发送数据。
 */
#pragma once

#include <prism/diagnose/diagnose.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/handshake/anytls/mux/session.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace psm::handshake::anytls
{
    using namespace psm::diagnose; // NOLINT(google-build-using-namespace)

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

        /**
         * @brief 构造 AnyTLS stream 传输层
         * @param session 所属 AnyTLS 会话
         * @param stream_id 流 ID
         * @param channel 该流的数据 channel
         */
        explicit anytls_stream_transport(std::shared_ptr<anytls_session> session, std::uint32_t stream_id,
                                         std::shared_ptr<channel_type> channel)
            : session_(std::move(session)), stream_id_(stream_id), channel_(std::move(channel))
        {
        }

        /**
         * @brief 获取传输层类型
         * @return type::tcp
         */
        [[nodiscard]] auto transport_type() const noexcept -> type override
        {
            return type::tcp;
        }

        /**
         * @brief 获取内层传输
         * @return nullptr（无内层传输）
         */
        [[nodiscard]] auto next_layer() noexcept -> transmission * override
        {
            return nullptr;
        }
        /**
         * @brief 获取内层传输（const 版本）
         * @return nullptr（无内层传输）
         */
        [[nodiscard]] auto next_layer() const noexcept -> const transmission * override
        {
            return nullptr;
        }

        /**
         * @brief 获取执行器
         * @return channel 的执行器，用于协程调度
         */
        [[nodiscard]] auto executor() const -> executor_type override
        {
            return channel_->get_executor();
        }

        /**
         * @brief 异步读取数据
         * @details 优先消费 pending 缓冲区，耗尽后从 channel 异步接收。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，返回读取字节数
         */
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

            auto [recv_ec, chunk] = co_await channel_->async_receive(net::as_tuple(net::use_awaitable));

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

        /**
         * @brief 异步写入数据
         * @details 通过 session_->write_psh 发送 PSH 帧。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，返回写入字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            return session_->write_psh(stream_id_, buffer, ec);
        }

        /**
         * @brief 关闭传输层
         * @details 向 channel 投递连接重置信号，并异步发送 FIN 帧关闭流。
         */
        void close() override
        {
            // 先保存 executor，避免 reset 后 channel_ 为空导致空指针解引用
            auto saved_executor = channel_ ? channel_->get_executor() : session_->get_transport_executor();
            if (channel_)
            {
                channel_->try_send(
                    boost::system::errc::make_error_code(boost::system::errc::connection_reset),
                    memory::vector<std::uint8_t>{});
                channel_ = nullptr;
            }
            // 发送 FIN
            auto self = session_;
            auto sid = stream_id_;
            net::co_spawn(
                saved_executor,
                [self, sid]() -> net::awaitable<void>
                {
                    try
                    {
                        std::error_code ec;
                        co_await self->write_fin(sid, ec);
                    }
                    catch (...)
                    {
                        diagnose::error("write_fin exception for stream_id={}", sid);
                    }
                },
                net::detached);
        }

        /**
         * @brief 取消所有未完成的异步操作
         * @details 等价于 close()。
         */
        void cancel() override
        {
            close();
        }

    private:
        std::shared_ptr<anytls_session> session_;     // 所属 AnyTLS 会话
        std::uint32_t stream_id_;                     // 流 ID
        std::shared_ptr<channel_type> channel_;       // 该流的数据 channel
        memory::vector<std::uint8_t> pending_buffer_; // 超出用户缓冲区的剩余数据
        std::size_t pending_offset_{0};               // pending 缓冲区消费游标
    };
} // namespace psm::handshake::anytls
