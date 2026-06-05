#include <prism/transport/preview.hpp>
#include <prism/memory/container.hpp>
#include <prism/trace.hpp>

#include <boost/asio/any_completion_handler.hpp>

#include <cstring>

using namespace psm::trace;

namespace psm::transport
{

    preview::preview(shared_transmission inner, std::span<const std::byte> preread, memory::resource_pointer mr)
        : inner_(std::move(inner)), preread_buffer_(preread.begin(), preread.end(), memory::effective_mr(mr))
    {
    }

    auto preview::executor() const
        -> executor_type
    {
        if (!inner_)
        {
            trace::error("preview::executor() called with null inner transport");
            return executor_type{};
        }
        return inner_->executor();
    }

    auto preview::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (offset_ < preread_buffer_.size())
        {
            const auto remaining = preread_buffer_.size() - offset_;
            const auto to_copy = (std::min)(remaining, buffer.size());
            if (to_copy > 0)
            {
                std::memcpy(buffer.data(), preread_buffer_.data() + offset_, to_copy);
                offset_ += to_copy;
            }
            ec.clear();
            co_return to_copy;
        }

        if (!inner_)
        {
            ec = std::make_error_code(std::errc::bad_file_descriptor);
            co_return 0;
        }

        co_return co_await inner_->async_read_some(buffer, ec);
    }

    auto preview::async_write_some(const std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (!inner_)
        {
            ec = std::make_error_code(std::errc::bad_file_descriptor);
            co_return 0;
        }
        co_return co_await inner_->async_write_some(buffer, ec);
    }

    void preview::close()
    {
        if (inner_)
        {
            inner_->close();
        }
    }

    void preview::cancel()
    {
        if (inner_)
        {
            inner_->cancel();
        }
    }

    void preview::async_read_some(std::span<std::byte> buffer, net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
    {
        if (offset_ < preread_buffer_.size())
        {
            const auto remaining = preread_buffer_.size() - offset_;
            const auto to_copy = (std::min)(remaining, buffer.size());
            if (to_copy > 0)
            {
                std::memcpy(buffer.data(), preread_buffer_.data() + offset_, to_copy);
                offset_ += to_copy;
            }
            std::move(handler)(boost::system::error_code{}, to_copy);
            return;
        }

        if (!inner_)
        {
            std::move(handler)(boost::system::error_code(
                static_cast<int>(std::errc::bad_file_descriptor),
                boost::system::generic_category()), 0);
            return;
        }

        inner_->async_read_some(buffer, std::move(handler));
    }

    void preview::async_write_some(std::span<const std::byte> buffer, net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
    {
        if (!inner_)
        {
            std::move(handler)(boost::system::error_code(
                static_cast<int>(std::errc::bad_file_descriptor),
                boost::system::generic_category()), 0);
            return;
        }

        inner_->async_write_some(buffer, std::move(handler));
    }

} // namespace psm::transport
