/**
 * @file transport.cpp
 * @brief gRPC (gun) 传输装饰器实现
 */

#include <prism/handshake/gun/transport.hpp>
#include <prism/handshake/gun/codec.hpp>

#include <cstring>

namespace psm::handshake::gun
{

    transport::transport(net::any_io_executor executor, write_cb write_fn,
                         const memory::resource_pointer mr)
        : executor_(std::move(executor))
        , write_fn_(std::move(write_fn))
        , mr_(mr)
        , channel_(std::make_unique<channel_type>(executor_, 512))
        , current_(mr)
    {
    }

    auto transport::executor() const -> executor_type
    {
        return executor_;
    }

    auto transport::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        while (current_offset_ >= current_.size())
        {
            if (closed_)
            {
                ec = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }

            boost::system::error_code ch_ec;
            auto token = net::redirect_error(net::use_awaitable, ch_ec);
            auto block = co_await channel_->async_receive(token);
            if (ch_ec)
            {
                ec = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (block.empty())
            {
                // 空块 = EOF 哨兵
                ec = psm::fault::make_error_code(psm::fault::code::eof);
                co_return 0;
            }
            current_ = std::move(block);
            current_offset_ = 0;
        }

        const auto n = std::min(buffer.size(), current_.size() - current_offset_);
        std::memcpy(buffer.data(), current_.data() + current_offset_, n);
        current_offset_ += n;
        ec = {};
        co_return n;
    }

    auto transport::async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (closed_ || !write_fn_)
        {
            ec = std::make_error_code(std::errc::not_connected);
            co_return 0;
        }

        // 封装为 gun 帧
        memory::vector<std::byte> frame(mr_);
        frame.resize(codec::header_fixed_len + codec::max_varint_len + buffer.size());
        const auto encoded = codec::encode_frame(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(buffer.data()), buffer.size()),
            std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(frame.data()), frame.size()));
        if (encoded == 0)
        {
            ec = std::make_error_code(std::errc::message_size);
            co_return 0;
        }
        frame.resize(encoded);

        co_await write_fn_(std::move(frame));
        ec = {};
        co_return buffer.size();
    }

    void transport::close()
    {
        closed_ = true;
        channel_->cancel();
    }

    void transport::cancel()
    {
        closed_ = true;
        channel_->cancel();
    }

    auto transport::push(const std::span<const std::byte> data) -> bool
    {
        if (closed_ || data.empty())
            return true;
        memory::vector<std::byte> copy(data.begin(), data.end(), mr_);
        return channel_->try_send(boost::system::error_code{}, std::move(copy));
    }

    void transport::notify_eof()
    {
        if (closed_)
            return;
        // 空块作为 EOF 哨兵
        channel_->try_send(boost::system::error_code{}, memory::vector<std::byte>(mr_));
    }

} // namespace psm::handshake::gun
