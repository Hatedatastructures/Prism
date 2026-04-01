/**
 * @file duct.cpp
 * @brief 多路复用 TCP 流管道实现
 * @details multiplex::duct 的双向转发实现。上行通过独立协程循环读取 target
 * 数据并发送到 mux；下行由帧循环直接 co_await 写入 target，天然反压。
 */

#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/core.hpp>
#include <prism/fault/handling.hpp>
#include <prism/trace.hpp>

#include <boost/asio/co_spawn.hpp>

constexpr std::string_view tag = "[Mux.Duct]";

namespace psm::multiplex
{
    namespace net = boost::asio;

    duct::duct(const std::uint32_t stream_id, std::shared_ptr<core> owner,
               channel::transport::shared_transmission target, const memory::resource_pointer mr)
        : id_(stream_id), owner_(std::move(owner)), mr_(mr),
          target_(std::move(target)), recv_buffer_(mr)
    {
        recv_buffer_.resize(owner_->config_.buffer_size);
    }

    duct::~duct()
    {
        close();
    }

    void duct::start()
    {
        auto self = shared_from_this();
        auto on_done = [self](const std::exception_ptr &ep)
        {
            if (ep)
            {
                try
                {
                    std::rethrow_exception(ep);
                }
                catch (const std::exception &e)
                {
                    trace::debug("{} stream {} uplink error: {}", tag, self->id_, e.what());
                }
                catch (...)
                {
                    trace::error("{} stream {} uplink unknown error", tag, self->id_);
                }
            }
            self->close();
        };
        net::co_spawn(target_->executor(), uplink_loop(), std::move(on_done));
    }

    auto duct::on_mux_data(const std::span<const std::byte> data) -> net::awaitable<void>
    {
        if (closed_)
        {
            co_return;
        }

        std::error_code ec;
        co_await target_->async_write(data, ec);
        if (ec)
        {
            trace::debug("{} stream {} write to target failed: {}", tag, id_, ec.message());
            close();
        }
    }

    void duct::on_mux_fin()
    {
        // mux 端半关闭，shutdown target 发送方向
        mux_closed_.store(true, std::memory_order_release);

        if (target_)
        {
            target_->shutdown_write();
            trace::debug("{} stream {} mux fin, shutdown send", tag, id_);
        }

        // target 端也已关闭，完全关闭管道
        if (target_closed_.load(std::memory_order_acquire))
        {
            close();
        }
    }

    void duct::close()
    {
        if (closed_)
        {
            return;
        }
        closed_ = true;

        if (target_)
        {
            target_->close();
            target_.reset();
        }

        try
        {
            owner_->remove_duct(id_);
        }
        catch (...)
        {
            trace::error("{} stream {} remove duct error", tag, id_);
        }

        trace::debug("{} stream {} closed", tag, id_);
    }

    auto duct::uplink_loop() -> net::awaitable<void>
    {
        std::error_code ec;

        // 持续从目标读取数据并发送到 mux
        while (!closed_)
        {
            const auto n = co_await target_->async_read_some(recv_buffer_, ec);
            if (ec || n == 0)
            {
                // 操作取消或 EOF 是正常关闭，不记录错误
                if (ec != std::errc::operation_canceled && fault::to_code(ec) != fault::code::eof)
                {
                    trace::debug("{} stream {} read from target failed: {}", tag, id_, ec.message());
                }
                break;
            }

            // 检查 mux 会话是否仍活跃
            if (!owner_->is_active())
            {
                break;
            }

            // 将数据发回 mux 客户端
            co_await owner_->send_data(id_, std::span(recv_buffer_.data(), n));
        }

        // 标记 target 端已关闭
        target_closed_.store(true, std::memory_order_release);

        // 如果 mux 端未关闭且会话仍活跃，通知 mux 关闭
        if (!mux_closed_.load(std::memory_order_acquire) && owner_->is_active())
        {
            owner_->send_fin(id_);
        }
    }

} // namespace psm::multiplex